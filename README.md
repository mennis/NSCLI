# NSCLI
The coraid HBA driver has a diagnostic interface that presents an entrypoint to a 9p filesystem. NSCLI is a tool that connects to that and behaves like a shell allowing you to cd, ls, and cat. The jcat option will produce nicely formated json output. You will find NSCLI is a little broken.  I no longer have access to coraid gear to test it and I'm not sure I'd have the heart to mess with it anyway. Coraid is dead; long live coraid.   

The ns filesystem entry provides a file interface into the namespace.  This means you use read and write operations that you would use to work with a file.  The tricky bit is that what you read and write are 9p messages.  http://en.wikipedia.org/wiki/9P will provide an overview and some links to the man page.  If you use -v with this script you will see the 9p communications in flight.  

There are many 9p implementations for use in different programming languages out there.  The trick to getting them to work with the HBA's namespace is that most of them assume you are handing them a socket.  The LocalNS, perhaps poorly named, simply replaces the socket semantics of Client with those of a file allowing this to work.  There are few hacks in here to get this to work with either my misunderstanding of the coraid 9p implementation or a bug in it.
