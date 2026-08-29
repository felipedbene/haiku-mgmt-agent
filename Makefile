# debeos-ssm-agent -- cross-build for haiku/arm64.
#
# There is no native toolchain on the target (NOTES.md 1: no gcc, no package
# repository), so this always cross-compiles. Build host prerequisites:
#   1. tools/stage-sysroot.sh   (Haiku headers + libs for the cross-tools)
#   2. tools/build-mbedtls.sh   (static TLS, since haiku/arm64 has no OpenSSL)
#
# Usage:  make            -- cross-build build/debeos-ssm-agent
#         make check      -- host-build and run the unit tests (needs host mbedTLS)
#         make clean

GEN         ?= /opt/haiku/haiku/generated.arm64
CT          ?= $(GEN)/cross-tools-arm64
CROSS       ?= aarch64-unknown-haiku
MBEDTLS     ?= /opt/haiku/mbedtls-arm64

CXX         := $(CT)/bin/$(CROSS)-g++
STRIP       := $(CT)/bin/$(CROSS)-strip

SRC         := src/json.cpp src/util.cpp src/log.cpp src/http.cpp src/aws.cpp \
               src/s3.cpp src/selfupdate.cpp \
               src/exec.cpp src/runner.cpp src/timesync.cpp src/main.cpp
OBJ         := $(patsubst src/%.cpp,build/%.o,$(SRC))
BIN         := build/debeos-ssm-agent

CXXFLAGS    ?= -std=c++17 -O2 -Wall -Wextra -Wno-unused-parameter
CXXFLAGS    += -I$(MBEDTLS)/include -Isrc
# Static TLS, so the binary has no dependency that haiku/arm64 cannot satisfy.
LDFLAGS     ?= -L$(MBEDTLS)/lib
LDLIBS      := -lmbedtls -lmbedx509 -lmbedcrypto -lnetwork

.PHONY: all clean check strip

all: $(BIN)

$(BIN): $(OBJ)
	@mkdir -p build
	$(CXX) $(OBJ) $(LDFLAGS) $(LDLIBS) -o $@
	@echo "built $@"

build/%.o: src/%.cpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -c $< -o $@

strip: $(BIN)
	$(STRIP) $(BIN)

# ---- host-side unit tests -------------------------------------------------
# Run the pure-logic tests (JSON, SigV4 vectors, parameter substitution,
# output truncation) on the build host, where a debugger exists.
HOST_CXX      ?= g++
HOST_MBEDTLS  ?= /usr
TEST_SRC      := tests/test_main.cpp src/json.cpp src/util.cpp src/log.cpp src/runner.cpp \
                 src/exec.cpp src/aws.cpp src/http.cpp src/s3.cpp
check:
	@mkdir -p build
	$(HOST_CXX) -std=c++17 -O1 -g -Wall -Isrc -I$(HOST_MBEDTLS)/include $(TEST_SRC) \
		-L$(HOST_MBEDTLS)/lib -lmbedtls -lmbedx509 -lmbedcrypto -o build/tests
	./build/tests

clean:
	rm -rf build
