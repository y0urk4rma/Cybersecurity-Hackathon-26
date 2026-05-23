# ─────────────────────────────────────────────────────────────────
# Makefile for hollow_detect
#
#  MinGW-w64:  make
#  MSVC:       nmake /f Makefile COMPILER=msvc
# ─────────────────────────────────────────────────────────────────

COMPILER ?= mingw

TARGET  = hollow_detect.exe
SOURCES = main.c engine.c analyzer.c checks.c \
          pe_utils.c process_utils.c report.c log.c

# ── MinGW-w64 ────────────────────────────────────────────────────
ifeq ($(COMPILER),mingw)
CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -Wno-unused-parameter \
          -D_WIN32_WINNT=0x0601 \
          -DWINVER=0x0601
LDFLAGS = -lntdll -lpsapi -ladvapi32 -lkernel32

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)
	@echo "[OK] Built: $(TARGET)"

clean:
	del /Q $(TARGET) *.o 2>nul || rm -f $(TARGET) *.o
endif

# ── MSVC (nmake) ─────────────────────────────────────────────────
ifeq ($(COMPILER),msvc)
CC      = cl
CFLAGS  = /nologo /O2 /W3 /D_WIN32_WINNT=0x0601 /DWINVER=0x0601
LIBS    = ntdll.lib psapi.lib advapi32.lib kernel32.lib

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) /Fe:$(TARGET) /link $(LIBS)

clean:
	del /Q $(TARGET) *.obj 2>nul
endif

.PHONY: clean
