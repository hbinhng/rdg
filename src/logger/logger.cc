#include "./logger.h"

#include <iomanip>
#include <iostream>
#include <string>

using namespace std;
using namespace Rdg;

const char *LOG_LEVELS[] = {"Error  ", "Warning", "Info   "};

void Logger::log(const string &message, ostream &stream, int level) {
  auto now = time(nullptr);

  stream << "[" << put_time(gmtime(&now), "%F %T") << "] - "
         << LOG_LEVELS[level] << " - " << message << endl;
}

void Rdg::Logger::error(const string &message) {
  Logger::log(message, cerr, 0);
}
void Rdg::Logger::warn(const string &message) { Logger::log(message, cout, 1); }
void Rdg::Logger::info(const string &message) { Logger::log(message, cout, 2); }