%define _unpackaged_files_terminate_build 0
%define _use_internal_dependency_generator 0

Name: deploy
Version: 1.0
Release: 1%{?dist}
Epoch: 1
Summary: Source Deploy daemon
License: GPLv3
Group: System Environment/Daemons
BuildRoot: %{_tmppath}/%{name}-root
BuildRequires: perl >= 0:5.00503
Source0: %{name}-%{version}.tar.bz2
Source1: deploy-agent.init
Source2: deploy-proxy.init
Source3: deploy.logrotate
Requires: perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version)) perl-IPC-ShareLite
BuildArch: noarch

%description
Deploy's features are as follows:
- Source sync
- Service daemon control

%package crypt
Group: Development/Languages
Summary: Deploy daemon crypt libs
Requires: deploy, perl-Crypt-OpenSSL-RSA, perl-Crypt-OpenSSL-AES, perl-Crypt-CBC

%description crypt
The libraries of protocol encryption

%package agent
Group: Development/Languages
Summary: Deploy agent daemon
Requires: deploy

%description agent
Deploy agent daemon

%package proxy
Group: Development/Languages
Summary: Deploy proxy daemon
Requires: deploy

%description proxy
Deploy proxy daemon

%package client
Group: Development/Languages
Summary: Deploy client
Requires: deploy

%description client
Deploy command line

%prep
%setup -q

%build

%{configure} --bindir=%{_bindir} --sbindir=%{_sbindir} --with-vendor-lib=%{perl_vendorlib}

%{__make}

%install
%{__rm} -rf %{buildroot}
%{__make} DESTDIR=%{buildroot} install
%{__install} -p -D -m 755 %{SOURCE1} %{buildroot}%{_initrddir}/deploy-agent
%{__install} -p -D -m 755 %{SOURCE2} %{buildroot}%{_initrddir}/deploy-proxy
%{__install} -d -m 755 %{buildroot}%{_localstatedir}/log/%{name}
%{__install} -p -D -m 644 %{SOURCE3} %{buildroot}%{_sysconfdir}/logrotate.d/deploy

%clean
%{__rm} -rf %{buildroot}

%post agent
/sbin/chkconfig --add deploy-agent
/sbin/chkconfig --level 35 deploy-agent on

%preun agent
if [ $1 = 0 ]; then
	/sbin/chkconfig --level 35 deploy-agent off
	/sbin/chkconfig --del deploy-agent
fi

%post proxy
/sbin/chkconfig --add deploy-proxy
/sbin/chkconfig --level 35 deploy-proxy on

%preun proxy
if [ $1 = 0 ]; then
	/sbin/chkconfig --level 35 deploy-proxy off
	/sbin/chkconfig --del deploy-proxy
fi

%files
%defattr(0644,root,root)
%{perl_vendorlib}/Deploy/*.pm
%config(noreplace) %{_sysconfdir}/logrotate.d/deploy
%dir %attr(0755,root,root) %{_localstatedir}/log/%{name}
%exclude %{perl_vendorlib}/Deploy/Crypt.pm

%files crypt
%defattr(0644,root,root)
%{perl_vendorlib}/Deploy/Crypt.pm

%files agent
%defattr(0644,root,root)
%attr(0750,root,root) %dir %{_sysconfdir}/deploy
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/deploy/deploy_agent.ini
%attr(0755,root,root) %{_initrddir}/deploy-agent
%attr(0755,root,root) %{_sbindir}/deploy-agent

%files proxy
%defattr(0644,root,root)
%attr(0750,root,root) %dir %{_sysconfdir}/deploy
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/deploy/deploy_proxy.ini
%attr(0755,root,root) %{_initrddir}/deploy-proxy
%attr(0755,root,root) %{_sbindir}/deploy-proxy

%files client
%defattr(0644,root,root)
%attr(0755,root,root) %{_sbindir}/deploy-client

%changelog
* Wed Dec 3 2014 YoungJoo.Kim <vozlt@vozlt.com> 1:1.0-1
- Initial package
