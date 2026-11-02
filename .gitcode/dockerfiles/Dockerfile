FROM swr.cn-north-4.myhuaweicloud.com/cloud_boostkit/openeuler22.03_lts_sp3:latest

LABEL maintainer="ttfhw-verify"
LABEL description="KAE (Kunpeng Accelerator Engine) pre-built environment for TTFHW verification"

RUN dnf update -y && dnf install -y \
    gcc \
    gcc-c++ \
    make \
    cmake \
    git \
    kernel-devel \
    kernel-headers \
    libtool \
    autoconf \
    automake \
    numactl-devel \
    numactl-libs \
    openssl-devel \
    lz4-devel \
    zstd-devel \
    libunwind-devel \
    chrpath \
    kmod \
    patch \
    perl \
    bzip2 \
    unzip \
    wget \
    tar \
    zlib-devel \
    && dnf clean all

RUN git clone --depth 1 --branch release-1.11.0 https://gitcode.com/gh_mirrors/go/googletest.git /opt/gtest && \
    rm -rf /opt/gtest/.git && \
    ls /opt/gtest

RUN KERNEL_VER=$(uname -r) && \
    KDEV_VER=$(rpm -q --qf '%{VERSION}-%{RELEASE}' kernel-devel 2>/dev/null | head -1) && \
    KDEV_ARCH=$(rpm -q kernel-devel --qf '%{ARCH}' 2>/dev/null | head -1) && \
    KDEV_PATH="/usr/src/kernels/${KDEV_VER}.${KDEV_ARCH}" && \
    BUILD_LINK="/lib/modules/${KERNEL_VER}/build" && \
    if [ ! -e "${BUILD_LINK}" ]; then \
        mkdir -p /lib/modules/${KERNEL_VER} && \
        ln -sf "${KDEV_PATH}" "${BUILD_LINK}"; \
    fi && \
    ldconfig && \
    rpm -q kernel-devel numactl-libs zstd-devel kmod chrpath

CMD ["/bin/bash"]
