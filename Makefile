CXXFLAGS 	= -O3 -Wall -Wextra -std=c++17 -march=native -s
INCLUDES 	= -Ithird-party/libtomcrypt/src/headers
LFLAGS		= -Lthird-party/libtomcrypt
LIBS 		= -lrocksdb -ltomcrypt
SRCS 		= hashcobra.cpp
OBJS 		= $(SRCS:.cpp=.o)
PROJECT 	= hashcobra
PREFIX		= /usr
SBINDIR		= $(PREFIX)/bin

.PHONY: depend $(PROJECT) clean

all: $(PROJECT)

$(PROJECT): depend $(OBJS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $(PROJECT) $(OBJS) $(LFLAGS) $(LIBS)

.cpp.o:
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $<  -o $@

clean:
	$(RM) *.o *~ $(PROJECT)
	$(MAKE) -C third-party/libtomcrypt clean

depend:
	$(MAKE) -C third-party/libtomcrypt

install: $(PROJECT)
	install -Dm 755 $(PROJECT) $(DESTDIR)/$(SBINDIR)/$(PROJECT)
	install -Dm 644 bash-completion/$(PROJECT) $(DESTDIR)/$(PREFIX)/share/bash-completion/completions/$(PROJECT)
	install -Dm 644 -t $(DESTDIR)/$(PREFIX)/share/doc/$(PROJECT)/ README.md
	install -Dm 644 LICENSE.md $(DESTDIR)/$(PREFIX)/share/licenses/$(PROJECT)/LICENSE.md

uninstall:
	rm -f $(DESTDIR)/$(SBINDIR)/$(PROJECT)
	rm -f $(DESTDIR)/$(PREFIX)/share/bash-completion/completions/$(PROJECT)
	rm -f $(DESTDIR)/$(PREFIX)/share/doc/$(PROJECT)/README.md
	rm -f $(DESTDIR)/$(PREFIX)/share/licenses/$(PROJECT)/LICENSE.md