#----------------------------------------------------------------------------
# rsabench - Copyright (c) 2025, Thierry Lelegard
# BSD 2-Clause License, see LICENSE file.
#----------------------------------------------------------------------------

default: exec

# SYSTEM = linux or mac, ARCH = x64 or arm64
SYSTEM := $(subst Linux,linux,$(subst Darwin,mac,$(shell uname -s)))
ARCH   := $(subst amd64,x64,$(subst x86_64,x64,$(subst aarch64,arm64,$(shell uname -m))))

# Project directories and files.
SRCDIR   = .
BINDIR   = build
EXEC     = $(BINDIR)/rsabench
SOURCES := $(wildcard $(SRCDIR)/*.cpp)
OBJECTS := $(patsubst $(SRCDIR)/%.cpp,$(BINDIR)/%.o,$(SOURCES))

# Tools and general options.
SHELL      = /usr/bin/env bash --noprofile
CXXFLAGS  += -Werror -Wall -Wextra -Wno-unused-parameter
FULLSPEED  = -O3 -fno-strict-aliasing -funroll-loops -fomit-frame-pointer
CPPFLAGS  += -std=c++17 $(if $(findstring mac,$(SYSTEM)),$(addprefix -I,$(wildcard /opt/homebrew/include /usr/local/include)))
LDFLAGS   += $(if $(findstring mac,$(SYSTEM)),$(addprefix -L,$(wildcard /opt/homebrew/lib /usr/local/lib)))
LDLIBS    += -lcrypto -lm

# Define DEBUG to compile in debug mode.
CXXFLAGS += $(if $(DEBUG),-g,-O2)
LDFLAGS  += $(if $(DEBUG),-g)

# To use a custom build of OpenSSL, clone https://github.com/openssl/openssl.git
# Then: ./config; make; make install DESTDIR=/some/where
# Build this project: make OSSLROOT=/some/where/usr/local
# Run the test: LD_LIBRARY_PATH=/some/where/usr/local/lib build/rsabench
CXXFLAGS += $(if $(OSSLROOT),-I$(OSSLROOT)/include)
LDFLAGS  += $(if $(OSSLROOT),-L$(OSSLROOT)/lib)

# Build operations.
exec: $(EXEC)
	@true
$(EXEC): $(OBJECTS)
	$(CXX) $(LDFLAGS) $^ $(LDLIBS) -o $@
$(BINDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(BINDIR)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c -o $@ $<
run: $(EXEC)
	$(EXEC)
clean:
	rm -rf build build-* core *.tmp *.log *.pro.user __pycache__

# Regenerate implicit dependencies.
ifneq ($(if $(MAKECMDGOALS),$(filter-out clean listvars cxxmacros,$(MAKECMDGOALS)),true),)
    -include $(patsubst $(SRCDIR)/%.cpp,$(BINDIR)/%.d,$(SOURCES))
endif
$(BINDIR)/%.d: $(SRCDIR)/%.cpp
	@mkdir -p $(BINDIR)
	$(CXX) -MM $(CPPFLAGS) -MT $(BINDIR)/$*.o -MT $@ $< >$@ || rm -f $@

# Display make variables for debug purposes.
listvars:
	@true
	$(foreach v, \
	  $(sort $(filter-out .% ^% @% _% *% \%% <% +% ?% BASH% LS_COLORS SSH% VTE% XDG% F_%,$(.VARIABLES))), \
	  $(info $(v) = "$($(v))"))

# Display C++ predefined macros for debug purposes.
cxxmacros:
	@$(CPP) $(CXXFLAGS) -x c++ -dM /dev/null | sort
