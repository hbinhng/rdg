#include "../logger/logger.h"
#include "session.h"

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <cstdio>
#include <cstdlib>
#include <iomanip>
#include <memory.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <resolv.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

using namespace Rdg;

int Session::resolveTarget(const string &host) {
  auto srvRecord = resolveSrv(host);

  if (srvRecord.second == 0)
    return 0;

  auto resolvedHost = srvRecord.first;
  auto port = srvRecord.second;

  Logger::info(slogpref + "Found SRV record associated with target - " +
               resolvedHost + ":" + to_string(port));

  addrinfo hints;
  addrinfo *result;

  memset(&hints, 0, sizeof(hints));

  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE; /* For wildcard IP address */
  hints.ai_protocol = 0;       /* Any protocol */
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  int getaddrinfoErrorCode;

  if ((getaddrinfoErrorCode =
           getaddrinfo(resolvedHost.c_str(), NULL, &hints, &result)) != 0) {
    Logger::error(slogpref + "Unable to resolve target");
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(getaddrinfoErrorCode));

    return 0;
  }

  for (auto i = result; i != NULL; i = i->ai_next) {
    this->upstreamFd = socket(AF_INET, SOCK_STREAM, 0);

    if (this->upstreamFd == -1)
      continue;

    ((sockaddr_in *)(i->ai_addr))->sin_port = htons(port);

    if (connect(this->upstreamFd, i->ai_addr, i->ai_addrlen) < 0) {
      close(this->upstreamFd);
      this->upstreamFd = 0;
      continue;
    }

    memcpy(&this->target, i->ai_addr, sizeof(this->target));
    break;
  }

  freeaddrinfo(result);

  if (this->upstreamFd <= 0) {
    Logger::error("Cannot connect to target upstream");

    return 0;
  }

  Logger::info(slogpref + "Target is " +
               string(inet_ntoa(((sockaddr_in *)&(this->target))->sin_addr)) +
               ":" + to_string(port));

  return 1;
}
