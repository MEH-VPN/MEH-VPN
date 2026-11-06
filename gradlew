#!/bin/sh
#
# Gradle start up script for POSIX generated for reproducible builds.
# Falls back to system gradle if gradle-wrapper.jar is not present.
#

APP_HOME=$( cd "${0%/*}" && pwd -P ) || exit
WRAPPER_JAR="$APP_HOME/gradle/wrapper/gradle-wrapper.jar"

if [ -f "$WRAPPER_JAR" ]; then
  if [ -n "$JAVA_HOME" ] && [ -x "$JAVA_HOME/bin/java" ]; then
    JAVACMD="$JAVA_HOME/bin/java"
  else
    JAVACMD="java"
  fi
  exec "$JAVACMD" -classpath "$WRAPPER_JAR" org.gradle.wrapper.GradleWrapperMain "$@"
else
  exec gradle "$@"
fi
