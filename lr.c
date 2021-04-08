/**
 * lr - a simple, fast link shortener
 * Copyright (C) 2021  anirudhb
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * How to use lr
 * =============
 *
 * lr is very simple to use.
 * To get started, compile this file. lr requires a C99 compiler, a libc that is
 * compliant to POSIX-1.2008, the socket library and the pthread library. These
 * are installed by default on most systems, so you can simply compile using:
 *  gcc -std=c99 -pthread -o lr lr.c
 *
 * Next, create the file links.csv in the current directory.
 * It should be an empty file.
 *
 * Third, setup the configuration below.
 * Lastly, you are ready to start lr! That's it!
 *
 * If a link gh->https://github.com is added for example,
 * example.com/gh will redirect to https://github.com.
 * Very simple.
 *
 * The on-disk format of the DB is CSV:
 *  gh,https://github.com
 *  yt,https://youtube.com
 * etc.
 *
 * Links can be inserted at runtime using the special endpoint
 * example.com/?insert. To insert a link, make a POST request to that endpoint.
 * Ensure that you include your API key in the Authorization header of the
 * request, like this: Authorization: Bearer qwertyuiop Then, add any number of
 * X-Insert-Link headers *after* the Authorization header, for each link you
 * would like to insert: X-Insert-Link: gh https://github.com X-Insert-Link: tw
 * https://twitter.com Note that if the X-Insert-Link headers precede the
 * Authorization header they will *not* be interpreted.
 *
 * That's all you need to start using lr!
 */

#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <netdb.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/** Configuration - modify this **/

// Port to listen on
#define PORT "8000"
// Number of worker threads
#define THREADS 4
// Allowed number of backlog connections
#define BACKLOG 10
// Filename to read and save links to
#define DB_FILENAME "links.csv"
// API key for adding links
#define API_KEY "qwertyuiop"

/** More advanced config - probably don't need to modify */

// Number of buckets for hashmap
#define HM_BUCKETS 17
// Buffer size for reading from socket (bytes)
#define BUFSIZE 1024

/**
 * Death functions
 */

#define d_die(fmt, ...)                                                        \
  do {                                                                         \
    fprintf(stderr, fmt "\n", ##__VA_ARGS__);                                  \
    exit(EXIT_FAILURE);                                                        \
  } while (0)

void d_pdie(const char *name) {
  perror(name);
  fprintf(stderr, "pdead\n");
  exit(EXIT_FAILURE);
}

void *d_malloc(size_t size) {
  void *r = malloc(size);
  if (r == NULL)
    d_pdie("malloc");
  return r;
}

void *d_realloc(void *ptr, size_t size) {
  void *new = realloc(ptr, size);
  if (new == NULL)
    d_pdie("realloc");
  return new;
}

void d_pthread_cond_signal(pthread_cond_t *__cond) {
  if (pthread_cond_signal(__cond) != 0)
    d_pdie("pthread_cond_signal");
}

void d_pthread_cond_wait(pthread_cond_t *__cond, pthread_mutex_t *__mutex) {
  if (pthread_cond_wait(__cond, __mutex) != 0)
    d_pdie("pthread_cond_wait");
}

void d_pthread_mutex_init(pthread_mutex_t *mutex,
                          const pthread_mutexattr_t *attr) {
  if (pthread_mutex_init(mutex, attr) != 0)
    d_pdie("pthread_mutex_init");
}

void d_pthread_mutex_lock(pthread_mutex_t *mutex) {
  if (pthread_mutex_lock(mutex) != 0)
    d_pdie("pthread_mutex_lock");
}

void d_pthread_mutex_unlock(pthread_mutex_t *mutex) {
  if (pthread_mutex_unlock(mutex) != 0)
    d_pdie("pthread_mutex_unlock");
}

void d_pthread_join(pthread_t thread, void **__thread_return) {
  if (pthread_join(thread, __thread_return) < 0)
    d_pdie("pthread_join");
}

void d_pthread_cancel(pthread_t thread) {
  if (pthread_cancel(thread) < 0)
    d_pdie("pthread_cancel");
}

void d_pthread_setcanceltype(int type, int *oldtype) {
  if (pthread_setcanceltype(type, oldtype) < 0)
    d_pdie("pthread_setcanceltype");
}

char *d_strtok_r(char *str, const char *delim, char **saveptr) {
  char *res = strtok_r(str, delim, saveptr);
  if (res == NULL)
    d_die("strtok_r failed");
  return res;
}

ssize_t d_read(int fd, void *buf, size_t count) {
  ssize_t res = read(fd, buf, count);
  if (res < 0)
    d_pdie("read");
  return res;
}

void d_dprintf(int fd, const char *fmt, ...) {
  va_list argp;
  va_start(argp, fmt);
  int res = vdprintf(fd, fmt, argp);
  va_end(argp);
  if (res < 0)
    d_pdie("vdprintf");
}

void d_fprintf(FILE *stream, const char *fmt, ...) {
  va_list argp;
  va_start(argp, fmt);
  int res = vfprintf(stream, fmt, argp);
  va_end(argp);
  if (res < 0)
    d_pdie("fprintf");
}

void d_getaddrinfo(const char *node, const char *service,
                   const struct addrinfo *hints, struct addrinfo **res) {
  if (getaddrinfo(node, service, hints, res) < 0)
    d_pdie("getaddrinfo");
}

int d_socket(int domain, int type, int protocol) {
  int res = socket(domain, type, protocol);
  if (res < 0)
    d_pdie("socket");
  return res;
}

void d_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  if (bind(sockfd, addr, addrlen) < 0)
    d_pdie("bind");
}

void d_setsockopt(int socket, int level, int option_name,
                  const void *option_value, socklen_t option_len) {
  if (setsockopt(socket, level, option_name, option_value, option_len) < 0)
    d_pdie("setsockopt");
}

void d_listen(int sockfd, int backlog) {
  if (listen(sockfd, backlog) < 0)
    d_pdie("listen");
}

int d_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  int res = accept(sockfd, addr, addrlen);
  if (res < 0)
    d_pdie("accept");
  return res;
}

void d_close(int fd) {
  if (close(fd) < 0)
    d_pdie("close");
}

void d_sigaction(int signum, const struct sigaction *act,
                 struct sigaction *oldact) {
  if (sigaction(signum, act, oldact) < 0)
    d_pdie("sigaction");
}

ssize_t d_getline(char **lineptr, size_t *n, FILE *stream) {
  ssize_t res = getline(lineptr, n, stream);
  if (res < -1)
    d_pdie("getline");
  return res;
}

void d_fclose(FILE *stream) {
  if (fclose(stream) < 0)
    d_pdie("fclose");
}

FILE *d_fopen(const char *pathname, const char *mode) {
  FILE *res = fopen(pathname, mode);
  if (res == NULL)
    d_pdie("fopen");
  return res;
}

/**
 * A simple, thread-safe job queue that builds on a singly-linked list.
 */

typedef struct {
  // socket fd
  int fd;
} tp_job_t;

typedef struct q_node_t {
  tp_job_t item;
  struct q_node_t *next;
} q_node_t;

typedef struct {
  pthread_mutex_t lock;
  // linked list
  q_node_t *head;
  q_node_t *tail;
} q_t;

// Initializes a new queue.
// This function is *not* thread-safe, unlike the rest.
void q_init(q_t *queue) {
  d_pthread_mutex_init(&queue->lock, NULL);
  queue->head = NULL;
  queue->tail = NULL;
}

// Adds a job to the queue and also signals the given condvar.
void q_append(q_t *queue, const tp_job_t *job, pthread_cond_t *condvar) {
  d_pthread_mutex_lock(&queue->lock);
  q_node_t *new = malloc(sizeof(q_node_t));
  memset(new, 0, sizeof(q_node_t));
  new->item = *job;
  if (queue->head == NULL || queue->tail == NULL) {
    queue->head = new;
    queue->tail = new;
  } else {
    queue->tail->next = new;
    queue->tail = new;
  }
  if (condvar != NULL) {
    pthread_cond_signal(condvar);
  }
  d_pthread_mutex_unlock(&queue->lock);
}

// Pops an item from the front of the queue
// into the given pointer.
// Returns true if an item was successfully popped.
bool q_pop_front(q_t *queue, tp_job_t *item) {
  d_pthread_mutex_lock(&queue->lock);
  if (queue->head != NULL) {
    q_node_t *node = queue->head;
    *item = node->item;
    queue->head = node->next;
    free(node);
    d_pthread_mutex_unlock(&queue->lock);
    return true;
  } else {
    d_pthread_mutex_unlock(&queue->lock);
    return false;
  }
}

/**
 * A simple pthread pool with job handling.
 */

struct tp_worker_thread_t;
struct tp_threadpool_t;

void handle_connection(int fd);

struct tp_threadpool_t {
  size_t num_threads;
  size_t next_thread_job_index;
  struct tp_worker_thread_t *threads;
  pthread_mutex_t should_quit_lock;
  bool should_quit;
  q_t jobs;
  pthread_cond_t jobs_notify;
};
typedef struct tp_threadpool_t tp_threadpool_t;

struct tp_worker_thread_t {
  pthread_t thread;
};
typedef struct tp_worker_thread_t tp_worker_thread_t;

// Returns whether a threadpool's workers should quit.
bool tp_threadpool_workers_should_quit(tp_threadpool_t *tp) {
  d_pthread_mutex_lock(&tp->should_quit_lock);
  bool res = tp->should_quit;
  d_pthread_mutex_unlock(&tp->should_quit_lock);
  return res;
}

void *tp_worker_thread_worker(void *inp) {
  tp_threadpool_t *tp = inp;
  while (!tp_threadpool_workers_should_quit(tp)) {
    tp_job_t job;
    while (q_pop_front(&tp->jobs, &job)) {
      handle_connection(job.fd);
    }
    // take the jobs lock and wait
    d_pthread_mutex_lock(&tp->jobs.lock);
    d_pthread_cond_wait(&tp->jobs_notify, &tp->jobs.lock);
    d_pthread_mutex_unlock(&tp->jobs.lock);
  }
  pthread_exit(EXIT_SUCCESS);
  return NULL;
}

void tp_worker_thread_init(tp_threadpool_t *tp, tp_worker_thread_t *worker) {
  pthread_create(&worker->thread, NULL, tp_worker_thread_worker, tp);
}

// Joins the given worker thread.
void tp_worker_thread_join(tp_worker_thread_t *worker) {
  d_pthread_join(worker->thread, NULL);
}

// Initializes a new threadpool with the given number of threads.
// The number of threads a threadpool contains cannot be changed
// after it is created.
void tp_threadpool_init(tp_threadpool_t *tp, size_t num_threads) {
  d_pthread_mutex_init(&tp->should_quit_lock, NULL);
  tp->next_thread_job_index = 0;
  tp->num_threads = num_threads;
  // allocate worker threads
  tp->threads = malloc(sizeof(tp_worker_thread_t) * num_threads);
  for (int i = 0; i < num_threads; i++) {
    tp_worker_thread_init(tp, &tp->threads[i]);
  }
  q_init(&tp->jobs);
}

// Adds a job to the thread pool.
void tp_threadpool_add_job(tp_threadpool_t *tp, const tp_job_t *job) {
  q_append(&tp->jobs, job, &tp->jobs_notify);
}

// Quits the given thread pool.
void tp_threadpool_quit(tp_threadpool_t *tp) {
  d_pthread_mutex_lock(&tp->should_quit_lock);
  tp->should_quit = true;
  d_pthread_mutex_unlock(&tp->should_quit_lock);
  free(tp->threads);
}

/**
 * Growable string utilities
 */

// Creates an empty string that can be appended to
char *s_new() {
  char *ptr = d_malloc(1);
  *ptr = '\0';
  return ptr;
}

// Similar to s_append but takes the length of the second string directly.
void s_appendn(char **s, const char *app, size_t appsize) {
  size_t newsize = strlen(*s) + appsize + 1;
  *s = d_realloc(*s, newsize);
  strncat(*s, app, appsize);
  (*s)[newsize - 1] = '\0';
}

// Appends the second string to the first, modifying the first string.
void s_append(char **s, const char *app) { s_appendn(s, app, strlen(app)); }

/**
 * Socket utilities
 */

// Reads a line from the socket.
char *sock_readline(int fd, char *buf, size_t bufsize, char **saveptr) {
  if (*saveptr == NULL || *saveptr > buf + bufsize)
    *saveptr = buf;
  char *newbuf = s_new();
  char *res = *saveptr;
  char *res2 = NULL;
  /* Add previous contents of buffer first */
  if ((res2 = strstr(res, "\r\n")) != NULL) {
    // Got a line in buffer, no need to actually read
    s_appendn(&newbuf, res, res2 - res);
    *saveptr = res2 + 2;
    return newbuf;
  } else if (*saveptr != buf) {
    // Append everything
    s_appendn(&newbuf, res, (buf + bufsize) - res);
  }
  d_read(fd, buf, bufsize);
  while ((res = strstr(buf, "\r\n")) == NULL) {
    s_appendn(&newbuf, buf, bufsize);
    d_read(fd, buf, bufsize);
  }
  s_appendn(&newbuf, buf, res - buf);
  // Skip the \r\n
  *saveptr = res + 2;
  return newbuf;
}

/**
 * A simple string->string hash map
 */

#define FNV_OFFSET_BASIS 0xcbf29ce484222325
#define FNV_PRIME 0x100000001b3

// FNV-1a implementation for strings
uint64_t hm_fnv1a(const char *s) {
  uint64_t hash = FNV_OFFSET_BASIS;
  for (const char *p = s; *p != '\0'; p++) {
    hash = (hash ^ *p) * FNV_PRIME;
  }
  return hash;
}

struct hm_ll_node_t {
  uint64_t hash;
  char *first;
  char *second;
  struct hm_ll_node_t *next;
};
typedef struct hm_ll_node_t hm_ll_node_t;

typedef struct {
  hm_ll_node_t *buckets[HM_BUCKETS];
} hm_t;

// Initializes the given hashmap.
void hm_init(hm_t *hm) { memset(hm, 0, sizeof(hm_t)); }

// Inserts an element into the hashmap.
void hm_insert(hm_t *hm, char *key, char *value) {
  uint64_t hash = hm_fnv1a(key);
  hm_ll_node_t **prev = &hm->buckets[hash % HM_BUCKETS];
  while (*prev != NULL) {
    if ((*prev)->hash == hash) {
      // can't free the value ptr since we don't know where it came from
      d_die("Trying to insert existing key into hashmap!");
    }
    *prev = (*prev)->next;
  }
  hm_ll_node_t *new = d_malloc(sizeof(hm_ll_node_t));
  new->hash = hash;
  new->first = key;
  new->second = value;
  new->next = *prev == NULL ? NULL : (*prev)->next;
  if ((*prev) == NULL)
    *prev = new;
  else
    (*prev)->next = new;
}

// Gets an element in the hashmap
// Returns NULL if the key was not found
const char *hm_get(hm_t *hm, const char *key) {
  uint64_t hash = hm_fnv1a(key);
  hm_ll_node_t *node = hm->buckets[hash % HM_BUCKETS];
  while (node != NULL && node->hash != hash)
    node = node->next;
  if (node == NULL)
    return NULL;
  else
    return node->second;
}

typedef struct {
  hm_t *hm;
  size_t i;
  hm_ll_node_t *ptr;
} hm_iter_t;

// Initializes a iterator through a hashmap
void hm_iter_init(hm_t *hm, hm_iter_t *iter) {
  iter->hm = hm;
  iter->i = 0;
  iter->ptr = NULL;
}

// Gets the next item in a hashmap iterator
// Returns NULL if the iterator is finished
hm_ll_node_t *hm_iter_next(hm_iter_t *iter) {
  if (iter->ptr != NULL) {
    iter->ptr = iter->ptr->next;
    if (iter->ptr != NULL)
      return iter->ptr;
  }
  while (iter->ptr == NULL && iter->i < HM_BUCKETS) {
    iter->ptr = iter->hm->buckets[iter->i++];
  }
  if (iter->ptr == NULL)
    return NULL;
  return iter->ptr;
}

// Destroys a hashmap
void hm_destroy(hm_t *hm) {
  // Destroy the linked list items
  for (int i = 0; i < HM_BUCKETS; i++) {
    hm_ll_node_t *bucket = hm->buckets[i];
    while (bucket != NULL) {
      free(bucket->first);
      free(bucket->second);
      hm_ll_node_t *next = bucket->next;
      free(bucket);
      bucket = next;
    }
  }
}

/**
 * HTTP handling
 */

// HTTP request line
typedef struct {
  // Request line - method & path point into this
  char *request_line;
  // Request method
  char *method;
  // Request path
  char *path;
} http_request_line;

// Frees a HTTP request line
void http_request_line_free(http_request_line *req) { free(req->request_line); }

// Reads a HTTP request line
void http_request_line_read(int fd, http_request_line *req, char *buf,
                            size_t bufsize, char **saveptr) {
  char *rl_saveptr;
  // char buf[64] = {0};
  char *line = sock_readline(fd, buf, bufsize, saveptr);
  req->request_line = line;
  req->method = d_strtok_r(line, " ", &rl_saveptr);
  req->path = d_strtok_r(NULL, " ", &rl_saveptr);
  char *http_version = d_strtok_r(NULL, " ", &rl_saveptr);
  if (strcmp(http_version, "HTTP/1.1") != 0 &&
      strcmp(http_version, "HTTP/1.0") != 0)
    d_die("Error validating HTTP version: Got %s but expected 1.0 or 1.1",
          http_version);
}

typedef struct {
  // Header line - name & value point into this
  char *header_line;
  // Header name
  char *name;
  // Header value
  char *value;
} http_header_t;

// Frees a HTTP header line
void http_header_free(http_header_t *header) { free(header->header_line); }

// Reads a HTTP header, returning false if no header was read.
// If this functions returns false, the body should start to be read
bool http_header_read(int fd, http_header_t *header, char *buf, size_t bufsize,
                      char **saveptr) {
  char *line = sock_readline(fd, buf, bufsize, saveptr);
  if (strlen(line) <= 0) {
    free(line);
    return false;
  }
  // Split
  header->header_line = line;
  char *hl_saveptr;
  header->name = d_strtok_r(line, ": ", &hl_saveptr);
  // FIXME: is this non-standard behavior?
  header->value = d_strtok_r(NULL, "", &hl_saveptr);
  return true;
}

// Writes the HTTP response line
void http_response_line_write(int fd, int status) {
  const char *reason = NULL;
  switch (status) {
  case 200:
    reason = "OK";
    break;
  case 204:
    reason = "No Content";
    break;
  case 301:
    reason = "Moved Permanently";
    break;
  case 302:
    reason = "Found";
    break;
  case 307:
    reason = "Temporary Redirect";
    break;
  case 403:
    reason = "Forbidden";
    break;
  case 404:
    reason = "Not Found";
    break;
  case 405:
    reason = "Method Not Allowed";
    break;
  }
  if (reason == NULL)
    d_die("Could not find a reason phrase for status %d!", status);
  d_dprintf(fd, "HTTP/1.1 %d %s\r\n", status, reason);
}

// Writes a HTTP header
void http_response_write_header(int fd, const char *name, const char *value) {
  d_dprintf(fd, "%s: %s\r\n", name, value);
}

// Ends an HTTP response's headers and allows the body to start.
void http_response_end_headers(int fd) { d_dprintf(fd, "\r\n"); }

// Standard HTTP headers
const char *H_LOCATION = "Location";

/**
 * Connection handling
 */

static hm_t hm;
static pthread_mutex_t hm_lock;

void handle_connection(int fd) {
  char buf[BUFSIZE] = {0};
  char *saveptr = NULL;
  http_request_line req;
  http_request_line_read(fd, &req, buf, BUFSIZE, &saveptr);
  if (strcmp(req.path, "/?insert") == 0) {
    if (strcmp(req.method, "POST") != 0) {
      http_response_line_write(fd, 405);
      goto done;
    }
    // Check auth
    http_header_t header;
    bool authenticated = false;
    while (http_header_read(fd, &header, buf, BUFSIZE, &saveptr)) {
      if (strcmp(header.name, "Authorization") == 0) {
        // Check that the value is in format "Bearer XYZ"
        char *hl_saveptr;
        const char *bearer = d_strtok_r(header.value, " ", &hl_saveptr);
        const char *api_key = d_strtok_r(NULL, " ", &hl_saveptr);
        if (strcmp(bearer, "Bearer") == 0 && strcmp(api_key, API_KEY) == 0) {
          authenticated = true;
        }
        http_header_free(&header);
        break;
      } else {
        http_header_free(&header);
      }
    }
    if (!authenticated) {
      http_response_line_write(fd, 403);
      goto done;
    }
    // Read X-Insert-Link headers
    while (http_header_read(fd, &header, buf, BUFSIZE, &saveptr)) {
      if (strcmp(header.name, "X-Insert-Link") == 0) {
        // Check the value to be in the form x:y
        char *hl_saveptr;
        char *link_name = d_strtok_r(header.value, " ", &hl_saveptr);
        char *link_value = strtok_r(NULL, " ", &hl_saveptr);
        if (link_value != NULL) {
          // Duplicate strings so that allocation can be freed
          link_name = strdup(link_name);
          link_value = strdup(link_value);
          d_pthread_mutex_lock(&hm_lock);
          printf("Inserting %s -> %s\n", link_name, link_value);
          hm_insert(&hm, link_name, link_value);
          d_pthread_mutex_unlock(&hm_lock);
        }
      }
      http_header_free(&header);
      // OK
      http_response_line_write(fd, 204);
    }
  } else {
    const char *link = req.path + 1;
    printf("Got link: %s\n", link);
    if (*link == '\0') {
      http_response_line_write(fd, 404);
      goto done;
    }
    const char *res;
    d_pthread_mutex_lock(&hm_lock);
    res = hm_get(&hm, link);
    d_pthread_mutex_unlock(&hm_lock);
    if (res == NULL) {
      http_response_line_write(fd, 404);
      goto done;
    }
    http_response_line_write(fd, 302);
    http_response_write_header(fd, H_LOCATION, res);
  }
done:
  http_response_end_headers(fd);
  http_request_line_free(&req);
  d_close(fd);
}

static int sockfd;
static tp_threadpool_t tp = {0};
static bool running = true;

void int_sighandler(int sig) {
  // Stop threadpool
  printf("Stopping threadpool...\n");
  tp_threadpool_quit(&tp);
  printf("Writing links to file...\n");
  d_pthread_mutex_lock(&hm_lock);
  /* Serialize the hashmap */
  FILE *f = d_fopen(DB_FILENAME, "w");
  hm_iter_t iter;
  hm_iter_init(&hm, &iter);
  hm_ll_node_t *item;
  while ((item = hm_iter_next(&iter)) != NULL) {
    printf("Writing item %s -> %s\n", item->first, item->second);
    d_fprintf(f, "%s,%s\n", item->first, item->second);
  }
  d_fclose(f);
  printf("Destroying hashmap\n");
  hm_destroy(&hm);
  // Don't unlock the mutex - hm cannot be accessed anymore
  printf("Closing socket...\n");
  d_close(sockfd);
  printf("Bye!\n");
  exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
  struct sigaction action = {0};
  action.sa_handler = int_sighandler;
  d_sigaction(SIGINT, &action, NULL);
  d_sigaction(SIGTERM, &action, NULL);

  struct addrinfo hints, *res;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  d_getaddrinfo(NULL, PORT, &hints, &res);
  printf("Got addrinfo\n");

  static int yes = 1;

  sockfd = d_socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  d_setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

  d_bind(sockfd, res->ai_addr, res->ai_addrlen);
  freeaddrinfo(res);
  d_listen(sockfd, BACKLOG);

  printf("Listening on socket...\n");

  tp_threadpool_init(&tp, THREADS);

  printf("Initialized threadpool\n");

  d_pthread_mutex_init(&hm_lock, NULL);
  d_pthread_mutex_lock(&hm_lock);
  hm_init(&hm);

  /* Setup the hashmap */
  FILE *f = d_fopen(DB_FILENAME, "r");
  char *line = NULL;
  size_t n = 0;
  while (d_getline(&line, &n, f) > 0) {
    // strtok
    char *saveptr;
    char *name = d_strtok_r(line, ",", &saveptr);
    char *value = d_strtok_r(NULL, "\n", &saveptr);
    printf("Inserting %s -> %s\n", name, value);
    hm_insert(&hm, strdup(name), strdup(value));
  }
  // free the line
  free(line);
  d_fclose(f);
  d_pthread_mutex_unlock(&hm_lock);

  printf("Initialized hashmap\n");

  struct sockaddr_storage their_addr;

  while (true) {
    socklen_t their_addrsize = sizeof(their_addr);
    int newfd =
        d_accept(sockfd, (struct sockaddr *)&their_addr, &their_addrsize);
    printf("Got connection\n");
    tp_job_t job;
    job.fd = newfd;
    tp_threadpool_add_job(&tp, &job);
  }
}
