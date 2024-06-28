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

pair<string, int> Session::resolveSrv(const string &host) {
  struct __res_state dnsstate;

  if (res_ninit(&dnsstate) < 0) {
    return make_pair("", 0);
  }

  dnsstate.retrans = 1000;

  union {
    HEADER header;
    unsigned char buffer[512];
  } name;
  string query = DNS_PREFIX + host;

  int resultLength =
      res_nquery(&dnsstate, query.c_str(), ns_c_in, ns_t_srv, name.buffer, 512);

  if (resultLength <= 0 || name.header.ancount == 0)
    return make_pair("", 0);

  ns_msg nameMessages;
  ns_rr record;

  ns_initparse(name.buffer, resultLength, &nameMessages);

  int port;
  string resolvedHost;

  for (int i = 0; i < ns_msg_count(nameMessages, ns_s_an); i++) {
    ns_parserr(&nameMessages, ns_s_an, i, &record);

    port = (int)record.rdata[4] * 256 + record.rdata[5];

    stringstream hoststream;

    for (int j = 6; j < record.rdlength - 1; j++) {
      int partLength = record.rdata[j];

      hoststream << string((char *)(record.rdata + j + 1), partLength) << ".";

      j += partLength;
    }

    resolvedHost = hoststream.str();
    resolvedHost = resolvedHost.substr(0, resolvedHost.length() - 1);

    if (resolvedHost.length() != 0)
      break;
  }

  if (resolvedHost.length() == 0) {
    Logger::error(slogpref + "Target not found");
    return make_pair("", 0);
  }

  return make_pair(resolvedHost, port);
}
