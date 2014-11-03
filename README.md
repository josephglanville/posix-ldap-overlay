This script is a Perl implemementation of an LDAP proxy that overlays and rewrites required attributes ontop of Active Directory for POSIX authentication.

It requires zero modifications to the upstream Active Directory infrastructure and can be used with older versions of nslcd etc that don't support the ability to map objectSid -> uidNumber/gidNumber etc.
