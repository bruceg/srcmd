Name: @PACKAGE@
Summary: Secure Remote Command Client
Version: @VERSION@
Release: 1
Copyright: GPL
Group: Utilities/System
Source: http://untroubled.org/@PACKAGE@/@PACKAGE@-@VERSION@.tar.gz
URL: http://untroubled.org/@PACKAGE@/
Packager: Bruce Guenter <bruceg@em.ca>
BuildRoot: %{_tmppath}/@PACKAGE@-buildroot
BuildRequires: bglibs >= 1.009

%description
Secure Remote Command client

%prep
%setup
#echo gcc "%{optflags}" >conf-cc
#echo gcc -s >conf-ld
echo %{_bindir} >conf-bin

%build
make

%install
rm -fr %{buildroot}
rm -f conf_bin.c insthier.o installer instcheck
echo %{buildroot}%{_bindir} >conf-bin
make installer instcheck

mkdir -p %{buildroot}%{_bindir}
./installer
./instcheck

mkdir -p %{buildroot}/etc/srcmd/host
#cp -a hosts %{buildroot}/etc/srcmd

%clean
rm -rf %{buildroot}

%post
if ! [ -e /etc/srcmd/host/secret ]; then
  srcmd-keygen /etc/srcmd/host
fi

%files
%defattr(-,root,root)
%doc ANNOUNCEMENT COPYING NEWS README
%dir /etc/srcmd
%dir /etc/srcmd/hosts
#%config(noreplace) /etc/srcmd/hosts/*
%{_bindir}/*
