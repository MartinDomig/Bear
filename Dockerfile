FROM ubuntu

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install --no-install-recommends -y \
    build-essential ca-certificates cmake daemonize dbus gdb gcovr git \
    libdbus-glib-1-dev libglib2.0-dev libsystemd-dev meson ninja-build \
    ssh systemd valgrind vim wget && apt clean

RUN userdel -r ubuntu

ARG UID=1000
ARG GID=1000
ARG UNAME=ubuntu

RUN groupadd -g $GID $UNAME
RUN useradd -m -u $UID -g $GID $UNAME
RUN echo "$UNAME ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
USER $UNAME
