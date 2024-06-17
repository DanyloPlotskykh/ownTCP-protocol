CC := g++
CFLAGS := -Wall -Wextra -std=c++17 -I../lib/include
SRCDIR := _client
BUILDDIR := ../build
LIBDIR := $(BUILDDIR)
INCDIR := ../lib/include

SRCS := main.cpp Sender.cpp
OBJS := $(SRCS:$(SRCDIR)/%.cpp=$(BUILDDIR)/%.o)
TARGET := $(BUILDDIR)/client

LIB := $(LIBDIR)/libtools.a
LIBFLAGS := -L$(LIBDIR) -ltools

$(TARGET): $(OBJS) $(LIB)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBFLAGS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp | $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

clean:
	rm -rf $(BUILDDIR)/*.o $(BUILDDIR)/$(TARGET)
