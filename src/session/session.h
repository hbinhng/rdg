#ifndef RDG_SESSION_SESSION_H
#define RDG_SESSION_SESSION_H

#include <arpa/inet.h>
#include <string>
#include <thread>

using namespace std;

namespace Rdg {
class Session {
private:
  static string DNS_PREFIX;
  static int BUFFER_SIZE;
  static int CONN_COUNT;

  int sockFd;
  int upstreamFd;
  int id;
  std::thread thread;
  std::thread forwardThread;
  string slogpref;
  char *buffer;
  char *downstreamBuffer;
  char *x224RequestBuffer;
  int x224RequestLength;
  bool terminated;

  string getRedirectionHost(int readBytes);
  pair<string, int> resolveSrv(const string &host);
  int resolveTarget(const string &host);

  sockaddr target;

public:
  Session(int sockFd);
  ~Session();

  void fork();

  static void sessionRoutine(Session *session);
  static void forwardRoutine(Session *session);
};
} // namespace Rdg

#endif // RDG_SESSION_SESSION_H