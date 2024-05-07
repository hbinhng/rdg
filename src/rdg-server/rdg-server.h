#ifndef RDG_RDG_SERVER_RDG_SERVER_H
#define RDG_RDG_SERVER_RDG_SERVER_H

#include <arpa/inet.h>
#include <string>

using namespace std;

namespace Rdg {
class RdgServer {
private:
  int sockFd;
  struct sockaddr_in address;

public:
  RdgServer(string host, int port);
  void run();
};
} // namespace Rdg

#endif // RDG_RDG_SERVER_RDG_SERVER_H