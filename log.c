#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <syslog.h>
#include "udp-link.h"

#ifdef LOG
void open_log(char *name, int opt1, int opt2)
{}

void write_log(int level, char *format, ...)
{
  va_list args;
  FILE *flog;
  time_t curtime;
  struct tm *curtm;
  char stime[256];
  char *p;

#ifdef LOG_STDOUT
  flog=stdout;
#else
  flog=fopen(LOG, "a");
  if (flog==NULL) return;
#endif
  curtime=time(NULL);
  curtm=localtime(&curtime);
  strcpy(stime, asctime(curtm));
  if ((p=strchr(stime, '\n'))!=NULL) *p='\0';
  fprintf(flog, "%s ", stime);
  switch (level)
  {
    case LOG_CRIT:   fprintf(flog, "CRIT: "); break;
    case LOG_ERR:    fprintf(flog, "ERR:  "); break;
    case LOG_NOTICE: fprintf(flog, "NOT:  "); break;
    case LOG_WARNING:fprintf(flog, "WARN: "); break;
    case LOG_INFO:   fprintf(flog, "INFO: "); break;
    case LOG_DEBUG:  fprintf(flog, "DEBG: "); break;
    default:         fprintf(flog, "UNKN: "); break;
  }
  va_start(args, format);
  vfprintf(flog, format, args);
  va_end(args);
  fprintf(flog, "\n");
#ifndef LOG_STDOUT
  fclose(flog);
#endif
}
#endif
