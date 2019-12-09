CXXFLAGS	= -O2 -Wall -Wextra -std=c++17
PREFIX		= /usr
SBINDIR		= $(PREFIX)/bin
PROJECT		= hashcobra
OBJ			= $(PROJECT).o
LIB			= -lcrypto -lrocksdb


all: $(PROJECT)

%.o: %.cpp
	$(CXX) -c -o $@ $< $(CXXFLAGS)

$(PROJECT): $(OBJ)
	$(CXX) $(LIB) -o $@ $^ $(CXXFLAGS)

.PHONY: clean

clean:
	rm -f *.o *~ core $(PROJECT)

install: $(PROJECT)
	install -Dm 755 $(PROJECT) $(DESTDIR)/$(SBINDIR)/$(PROJECT)
	install -Dm 644 -t $(DESTDIR)/$(PREFIX)/share/doc/$(PROJECT)/ README.md
	install -Dm 644 LICENSE.md $(DESTDIR)/$(PREFIX)/share/licenses/$(PROJECT)/LICENSE.md

uninstall:
	rm -f $(DESTDIR)/$(SBINDIR)/$(PROJECT)
	rm -f $(DESTDIR)/$(PREFIX)/share/doc/$(PROJECT)/README.md
	rm -f $(DESTDIR)/$(PREFIX)/share/licenses/$(PROJECT)/LICENSE.md