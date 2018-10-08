# == Class: ssh
#
# Manage ssh client and server
#
class ssh (
  Variant[String, Array[String[1]]] $packages = ['openssh-clients'],
  Boolean $key_export = false,
  Boolean $purge_keys = true,
  Optional[Stdlib::Absolutepath] $ssh_package_source = undef,
  Optional[Stdlib::Absolutepath] $ssh_package_adminfile = undef,
  Enum['present', 'absent'] $ssh_key_ensure = 'present',
  Boolean $ssh_key_import = true,
  Ssh::Key::Type $ssh_key_type = 'ssh-rsa',
  $ssh_config_hash_known_hosts = 'USE_DEFAULTS',
  $config_entries = {},
  $keys = undef,
  Stdlib::Absolutepath $ssh_config_path = '/etc/ssh/ssh_config',
  String[1] $ssh_config_owner = 'root',
  String[1] $ssh_config_group = 'root',
  Stdlib::Filemode $ssh_config_mode = '0644',
  $ssh_config_global_known_hosts_file = '/etc/ssh/ssh_known_hosts',
  $ssh_config_global_known_hosts_list = undef,
  $ssh_config_global_known_hosts_owner = 'root',
  $ssh_config_global_known_hosts_group = 'root',
  $ssh_config_global_known_hosts_mode = '0644',
  $manage_root_ssh_config = false,
  $root_ssh_config_content = "# This file is being maintained by Puppet.\n# DO NOT EDIT\n",
) {

  case $facts['os']['family'] {
    'RedHat': {
      $default_packages                        = ['openssh-server',
                                                  'openssh-clients']
      $default_service_name                    = 'sshd'
      $default_ssh_config_hash_known_hosts     = 'no'
      $default_ssh_config_forward_x11_trusted  = 'yes'
      $default_ssh_package_source              = undef
      $default_ssh_package_adminfile           = undef
      $default_ssh_sendenv                     = true
      $default_sshd_config_subsystem_sftp      = '/usr/libexec/openssh/sftp-server'
      $default_sshd_config_mode                = '0600'
      $default_sshd_config_use_dns             = 'yes'
      $default_sshd_config_xauth_location      = '/usr/bin/xauth'
      $default_sshd_use_pam                    = 'yes'
      $default_sshd_gssapikeyexchange          = undef
      $default_sshd_pamauthenticationviakbdint = undef
      $default_sshd_gssapicleanupcredentials   = 'yes'
      $default_sshd_acceptenv                  = true
      $default_service_hasstatus               = true
      if versioncmp($::operatingsystemrelease, '7.4') < 0 {
        $default_sshd_config_serverkeybits = '1024'
      } else {
        $default_sshd_config_serverkeybits = undef
      }
      $default_sshd_config_hostkey             = [ '/etc/ssh/ssh_host_rsa_key' ]
      $default_sshd_addressfamily              = 'any'
      $default_sshd_config_tcp_keepalive       = 'yes'
      $default_sshd_config_permittunnel        = 'no'
    }
    'Suse': {
      $default_packages                        = 'openssh'
      $default_service_name                    = 'sshd'
      $default_ssh_config_hash_known_hosts     = 'no'
      $default_ssh_package_source              = undef
      $default_ssh_package_adminfile           = undef
      $default_ssh_sendenv                     = true
      $default_ssh_config_forward_x11_trusted  = 'yes'
      $default_sshd_config_mode                = '0600'
      $default_sshd_config_use_dns             = 'yes'
      $default_sshd_config_xauth_location      = '/usr/bin/xauth'
      $default_sshd_use_pam                    = 'yes'
      $default_sshd_gssapikeyexchange          = undef
      $default_sshd_pamauthenticationviakbdint = undef
      $default_sshd_gssapicleanupcredentials   = 'yes'
      $default_sshd_acceptenv                  = true
      $default_service_hasstatus               = true
      $default_sshd_config_serverkeybits       = '1024'
      $default_sshd_config_hostkey             = [ '/etc/ssh/ssh_host_rsa_key' ]
      $default_sshd_addressfamily              = 'any'
      $default_sshd_config_tcp_keepalive       = 'yes'
      $default_sshd_config_permittunnel        = 'no'
      case $::architecture {
        'x86_64': {
          if ($::operatingsystem == 'SLES') and ($::operatingsystemrelease =~ /^12\./) {
            $default_sshd_config_subsystem_sftp = '/usr/lib/ssh/sftp-server'
          } else {
            $default_sshd_config_subsystem_sftp = '/usr/lib64/ssh/sftp-server'
          }
        }
        'i386' : {
          $default_sshd_config_subsystem_sftp = '/usr/lib/ssh/sftp-server'
      }
        default: {
          fail("ssh supports architectures x86_64 and i386 for Suse. Detected architecture is <${::architecture}>.")
        }
      }
    }
    'Debian': {
      # common for debian and ubuntu
      $default_packages                        = ['openssh-server',
                                                  'openssh-client']
      $default_service_name                    = 'ssh'

      case $::operatingsystemrelease {
        '16.04': {
          $default_sshd_config_hostkey = [
            '/etc/ssh/ssh_host_rsa_key',
            '/etc/ssh/ssh_host_dsa_key',
            '/etc/ssh/ssh_host_ecdsa_key',
            '/etc/ssh/ssh_host_ed25519_key',
          ]
          $default_ssh_config_hash_known_hosts        = 'yes'
          $default_sshd_config_xauth_location         = undef
          $default_ssh_config_forward_x11_trusted     = 'yes'
          $default_ssh_package_source                 = undef
          $default_ssh_package_adminfile              = undef
          $default_ssh_sendenv                        = true
          $default_sshd_config_subsystem_sftp         = '/usr/lib/openssh/sftp-server'
          $default_sshd_config_mode                   = '0600'
          $default_sshd_config_use_dns                = 'yes'
          $default_sshd_use_pam                       = 'yes'
          $default_sshd_gssapikeyexchange             = undef
          $default_sshd_pamauthenticationviakbdint    = undef
          $default_sshd_gssapicleanupcredentials      = 'yes'
          $default_sshd_acceptenv                     = true
          $default_service_hasstatus                  = true
          $default_sshd_config_serverkeybits          = '1024'
          $default_sshd_addressfamily                 = 'any'
          $default_sshd_config_tcp_keepalive          = 'yes'
          $default_sshd_config_permittunnel           = 'no'
        }
        '18.04': {
          $default_sshd_config_hostkey = [
            '/etc/ssh/ssh_host_rsa_key',
            '/etc/ssh/ssh_host_dsa_key',
            '/etc/ssh/ssh_host_ecdsa_key',
            '/etc/ssh/ssh_host_ed25519_key',
          ]
          $default_ssh_config_hash_known_hosts        = 'yes'
          $default_sshd_config_xauth_location         = undef
          $default_ssh_config_forward_x11_trusted     = 'yes'
          $default_ssh_package_source                 = undef
          $default_ssh_package_adminfile              = undef
          $default_ssh_sendenv                        = true
          $default_sshd_config_subsystem_sftp         = '/usr/lib/openssh/sftp-server'
          $default_sshd_config_mode                   = '0600'
          $default_sshd_config_use_dns                = 'yes'
          $default_sshd_use_pam                       = 'yes'
          $default_sshd_gssapikeyexchange             = undef
          $default_sshd_pamauthenticationviakbdint    = undef
          $default_sshd_gssapicleanupcredentials      = 'yes'
          $default_sshd_acceptenv                     = true
          $default_service_hasstatus                  = true
          $default_sshd_config_serverkeybits          = '1024'
          $default_sshd_addressfamily                 = 'any'
          $default_sshd_config_tcp_keepalive          = 'yes'
          $default_sshd_config_permittunnel           = 'no'
        }
        /^9.*/: {
          $default_sshd_config_hostkey = [
            '/etc/ssh/ssh_host_rsa_key',
            '/etc/ssh/ssh_host_ecdsa_key',
            '/etc/ssh/ssh_host_ed25519_key',
          ]
          $default_sshd_config_mode                = '0600'
          $default_sshd_use_pam                    = 'yes'
          $default_ssh_config_forward_x11_trusted  = 'yes'
          $default_sshd_acceptenv                  = true
          $default_sshd_config_subsystem_sftp      = '/usr/lib/openssh/sftp-server'
          $default_ssh_config_hash_known_hosts     = 'yes'
          $default_ssh_sendenv                     = true
          $default_sshd_addressfamily              = undef
          $default_sshd_config_serverkeybits       = undef
          $default_sshd_gssapicleanupcredentials   = undef
          $default_sshd_config_use_dns             = undef
          $default_sshd_config_xauth_location      = undef
          $default_sshd_config_permittunnel        = undef
          $default_sshd_config_tcp_keepalive       = undef
          $default_ssh_package_source              = undef
          $default_ssh_package_adminfile           = undef
          $default_sshd_gssapikeyexchange          = undef
          $default_sshd_pamauthenticationviakbdint = undef
          $default_service_hasstatus               = true
        }
        /^7.*/: {
          $default_sshd_config_hostkey             = [ '/etc/ssh/ssh_host_rsa_key' ]
          $default_ssh_config_hash_known_hosts     = 'no'
          $default_sshd_config_xauth_location      = '/usr/bin/xauth'
          $default_ssh_config_forward_x11_trusted  = 'yes'
          $default_ssh_package_source              = undef
          $default_ssh_package_adminfile           = undef
          $default_ssh_sendenv                     = true
          $default_sshd_config_subsystem_sftp      = '/usr/lib/openssh/sftp-server'
          $default_sshd_config_mode                = '0600'
          $default_sshd_config_use_dns             = 'yes'
          $default_sshd_use_pam                    = 'yes'
          $default_sshd_gssapikeyexchange          = undef
          $default_sshd_pamauthenticationviakbdint = undef
          $default_sshd_gssapicleanupcredentials   = 'yes'
          $default_sshd_acceptenv                  = true
          $default_service_hasstatus               = true
          $default_sshd_config_serverkeybits       = '1024'
          $default_sshd_addressfamily              = 'any'
          $default_sshd_config_tcp_keepalive       = 'yes'
          $default_sshd_config_permittunnel        = 'no'
        }
        /^8.*/: {

          $default_ssh_config_hash_known_hosts     = 'yes'
          $default_ssh_config_forward_x11_trusted  = 'yes'
          $default_ssh_package_source              = undef
          $default_ssh_package_adminfile           = undef
          $default_ssh_sendenv                     = true
          $default_sshd_config_hostkey = [
          '/etc/ssh/ssh_host_rsa_key',
          '/etc/ssh/ssh_host_dsa_key',
          '/etc/ssh/ssh_host_ecdsa_key',
          '/etc/ssh/ssh_host_ed25519_key',
          ]
          $default_sshd_config_subsystem_sftp      = '/usr/lib/openssh/sftp-server'
          $default_sshd_config_mode                = '0600'
          $default_sshd_config_use_dns             = 'yes'
          $default_sshd_use_pam                    = 'yes'
          $default_sshd_gssapikeyexchange          = undef
          $default_sshd_pamauthenticationviakbdint = undef
          $default_sshd_gssapicleanupcredentials   = undef
          $default_sshd_acceptenv                  = true
          $default_sshd_config_xauth_location      = undef
          $default_sshd_config_serverkeybits       = '1024'
          $default_sshd_addressfamily              = 'any'
          $default_sshd_config_tcp_keepalive       = 'yes'
          $default_sshd_config_permittunnel        = 'no'
          $default_service_hasstatus               = true
        }
        default: { fail ("Operating System : ${::operatingsystemrelease} not supported") }
      }
    }
    'Solaris': {
      $default_ssh_config_hash_known_hosts     = undef
      $default_ssh_sendenv                     = false
      $default_ssh_config_forward_x11_trusted  = undef
      $default_sshd_config_subsystem_sftp      = '/usr/lib/ssh/sftp-server'
      $default_sshd_config_mode                = '0644'
      $default_sshd_config_use_dns             = undef
      $default_sshd_config_xauth_location      = '/usr/openwin/bin/xauth'
      $default_sshd_use_pam                    = undef
      $default_sshd_gssapikeyexchange          = 'yes'
      $default_sshd_pamauthenticationviakbdint = 'yes'
      $default_sshd_gssapicleanupcredentials   = undef
      $default_sshd_acceptenv                  = false
      $default_sshd_config_serverkeybits       = '768'
      $default_ssh_package_adminfile           = undef
      $default_sshd_config_hostkey             = [ '/etc/ssh/ssh_host_rsa_key' ]
      $default_sshd_addressfamily              = undef
      $default_sshd_config_tcp_keepalive       = undef
      $default_sshd_config_permittunnel        = undef
      case $::kernelrelease {
        '5.11': {
          $default_packages                      = ['network/ssh',
                                                    'network/ssh/ssh-key',
                                                    'service/network/ssh']
          $default_service_name                  = 'ssh'
          $default_service_hasstatus             = true
          $default_ssh_package_source            = undef
        }
        '5.10': {
          $default_packages                      = ['SUNWsshcu',
                                                    'SUNWsshdr',
                                                    'SUNWsshdu',
                                                    'SUNWsshr',
                                                    'SUNWsshu']
          $default_service_name                  = 'ssh'
          $default_service_hasstatus             = true
          $default_ssh_package_source            = '/var/spool/pkg'
        }
        '5.9' : {
          $default_packages                      = ['SUNWsshcu',
                                                    'SUNWsshdr',
                                                    'SUNWsshdu',
                                                    'SUNWsshr',
                                                    'SUNWsshu']
          $default_service_name                  = 'sshd'
          $default_service_hasstatus             = false
          $default_ssh_package_source            = '/var/spool/pkg'
        }
        default: {
          fail('ssh module supports Solaris kernel release 5.9, 5.10 and 5.11.')
        }
      }
    }
    default: {
      fail("ssh supports osfamilies RedHat, Suse, Debian and Solaris. Detected osfamily is <${::osfamily}>.")
    }
  }

  if "${::ssh_version}" =~ /^OpenSSH/  { # lint:ignore:only_variable_string
    $ssh_version_array = split($::ssh_version_numeric, '\.')
    $ssh_version_maj_int = 0 + $ssh_version_array[0]
    $ssh_version_min_int = 0 + $ssh_version_array[1]
    if $ssh_version_maj_int > 5 {
      $default_ssh_config_use_roaming = 'no'
    } elsif $ssh_version_maj_int == 5 and $ssh_version_min_int >= 4 {
      $default_ssh_config_use_roaming = 'no'
    } else {
      $default_ssh_config_use_roaming = 'unset'
    }
  } else {
      $default_ssh_config_use_roaming = 'unset'
  }

  package { $packages:
    ensure    => installed,
    source    => $package_source,
    adminfile => $package_adminfile,
  }

  file  { 'ssh_config' :
    ensure  => file,
    path    => $ssh_config_path,
    owner   => $ssh_config_owner,
    group   => $ssh_config_group,
    mode    => $ssh_config_mode,
    content => template($ssh_config_template),
    require => Package[$packages],
  }

  if $manage_root_ssh_config == true {

    exec { "mkdir_p-${::root_home}/.ssh":
      command => "mkdir -p ${::root_home}/.ssh",
      unless  => "test -d ${::root_home}/.ssh",
      path    => '/bin:/usr/bin',
    }

    file { 'root_ssh_dir':
      ensure  => directory,
      path    => "${::root_home}/.ssh",
      owner   => 'root',
      group   => 'root',
      mode    => '0700',
      require => Exec["mkdir_p-${::root_home}/.ssh"],
    }

    file { 'root_ssh_config':
      ensure  => file,
      path    => "${::root_home}/.ssh/config",
      content => $root_ssh_config_content,
      owner   => 'root',
      group   => 'root',
      mode    => '0600',
    }
  }

  if $manage_service_real {
    service { 'sshd_service' :
      ensure     => $service_ensure,
      name       => $service_name_real,
      enable     => $service_enable_real,
      hasrestart => $service_hasrestart_real,
      hasstatus  => $service_hasstatus_real,
      subscribe  => File['sshd_config'],
    }
  }

  if $manage_firewall == true {
    firewall { '22 open port 22 for SSH':
      action => 'accept',
      dport  => 22,
      proto  => 'tcp',
    }
  }

  # If either IPv4 or IPv6 stack is not configured on the agent, the
  # corresponding $::ipaddress(6)? fact is not present. So, we cannot assume
  # these variables are defined. Getvar (Stdlib 4.13+, ruby 1.8.7+) handles
  # this correctly.
  if getvar('::ipaddress') and getvar('::ipaddress6') { $host_aliases = [$::hostname, $::ipaddress, $::ipaddress6] }
  elsif getvar('::ipaddress6') { $host_aliases = [$::hostname, $::ipaddress6] }
  else { $host_aliases = [$::hostname, $::ipaddress] }

  # export each node's ssh key
  if $key_export == true {
    # ssh_key_type might start with 'ssh-' though facter stores them without
    # the 'ssh-' prefix.
    $key_type = delete_regex($key_type, '^ssh-')
    @@sshkey { $::fqdn :
      ensure       => $ssh_key_ensure,
      host_aliases => $host_aliases,
      type         => $ssh_key_type,
      key          => $facts['ssh'][$key_type]['key'],
    }
  }

  file { 'ssh_known_hosts':
    ensure  => file,
    path    => $ssh_config_global_known_hosts_file,
    owner   => $ssh_config_global_known_hosts_owner,
    group   => $ssh_config_global_known_hosts_group,
    mode    => $ssh_config_global_known_hosts_mode,
    require => Package[$packages],
  }

  # import all nodes' ssh keys
  if $ssh_key_import == true {
    Sshkey <<||>> {
      target => $ssh_config_global_known_hosts_file,
    }
  }

  # remove ssh key's not managed by puppet
  resources  { 'sshkey':
    purge => $purge_keys,
  }

  # manage users' ssh config entries if present
  create_resources('ssh::config_entry',$config_entries)

  # manage users' ssh authorized keys if present
  if $keys != undef {
    if $hiera_merge == true {
      $keys = hiera_hash('ssh::keys')
    } else {
      $keys = $keys
      notice('Future versions of the ssh module will default ssh::hiera_merge to true')
    }
    validate_hash($keys)
    create_resources('ssh_authorized_key', $keys)
  }
}
