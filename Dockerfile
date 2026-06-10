# Base Image
FROM ubuntu:latest

# Install dependencies
RUN apt update && \
    DEBIAN_FRONTEND=noninteractive apt install -y \
    tpm2-tools tpm2-abrmd tpm2-openssl swtpm \
    autoconf \
    git \
    libtool \
    pkg-config \
    libssl-dev \
    openssl \
    libcrypto++-dev \
    libjson-c-dev \
    libcurl4-openssl-dev \
    libglib2.0-dev \
    libjson-glib-dev \
    libini-config-dev \
    gnutls-dev \
    libseccomp-dev \
    libc-bin \
    dbus \
    dbus-x11 \
    dbus-user-session \
    libdbus-1-dev \
    python3 \
    python3-pip \
    python3-setuptools \
    python3-mako \
    autoconf-archive \
    make \
    && apt clean

# Add TPM2 Software PPA and install TPM2-TSS
WORKDIR /opt
RUN git clone --depth=1 https://github.com/tpm2-software/tpm2-tss.git 

#COPY tpm2-tss /opt/tpm2-tss
WORKDIR /opt/tpm2-tss
RUN touch aminclude_static.am 

RUN echo 'm4_pattern_allow([AC_SUBST])\n\
m4_pattern_allow([AS_IF])\n\
m4_pattern_allow([AC_MSG_ERROR])\n\
m4_pattern_allow([AC_MSG_WARN])' | cat - configure.ac > temp && mv temp configure.ac

RUN ./bootstrap && \
    ./configure --disable-dependency-tracking --prefix=/usr && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# Install TPM Emulator (swtpm)
RUN apt-get update && apt-get install -y swtpm swtpm-tools

# Install Python dependencies
RUN pip3 install --break-system-packages fastapi uvicorn pydantic python-multipart

# Copy Python API files
COPY tpm2_api.py /opt/tpm2_api.py
COPY tpm2_rest_api.py /opt/tpm2_rest_api.py
COPY tpm2_cli.py /opt/tpm2_cli.py
COPY simple_tss2_tls_server.py /opt/simple_tss2_tls_server.py
COPY requirements.txt /opt/requirements.txt

# Make CLI executable
RUN chmod +x /opt/tpm2_cli.py
RUN chmod +x /opt/simple_tss2_tls_server.py

# Define entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set default command
ENTRYPOINT ["/entrypoint.sh"]
