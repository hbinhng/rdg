#ifndef RDG_RDG_SERVER_RDG_SERVER_H
#define RDG_RDG_SERVER_RDG_SERVER_H

#include "../session/session.h"

#include <arpa/inet.h>
#include <string>
#include <thread>

using namespace std;

namespace Rdg {
class RdgServer {
private:
  int sockFd;
  struct sockaddr_in address;
  thread *mainThread;

public:
  RdgServer(string host, int port);
  void run();

  int getSockFd();

  static void mainThreadRoutine(RdgServer *rdg);
};
} // namespace Rdg

#endif // RDG_RDG_SERVER_RDG_SERVER_H
