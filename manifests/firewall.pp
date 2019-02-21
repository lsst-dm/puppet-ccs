# A description of what this class does
#
# @summary A short summary of the purpose of this class
#
# @example
#   include ccs::firewall
class ccs::firewall (
  $tcp_subnets = [ { 'localhost' => '127.0.0.1/32' } ],
  $tcp_ports = [ '40404-40420' ],
  $udp_subnets = [ { 'localhost' => '127.0.0.1/32' } ],
  $udp_ports = [ '32400-32450' ],
  $multicast_subnets = [ { 'ccs-multicast' => '228.8.8.8/32' } ],
) {

  # TCP

  $tcp_subnets.each | $location, $source_cidr |
  {
    $tcp_ports.each | $index, $dport |
    {
      firewall { "400 allow ccs on tcp ports ${dport} from ${location}":
        proto  => tcp,
        dport  => $dport,
        source => $source_cidr,
        action => accept,
      }
    }
  }

  # UDP

  $udp_subnets.each | $location, $source_cidr |
  {
    $udp_ports.each | $index, $dport |
    {
      firewall { "400 allow ccs on udp ports ${dport} from ${location}":
        proto  => udp,
        dport  => $dport,
        source => $source_cidr,
        action => accept,
      }
    }
  }

  # MULTICAST
  # default multicast address for JGroups: 228.8.8.8
  # the ports are:  LOG 26969, STATUS 36969, COMMAND 46969
  # https://docs.jboss.org/jbossas/docs/Clustering_Guide/beta422/html/jbosscache-jgroups-transport-udp.html

  $multicast_subnets.each | $location, $source_cidr |
  {
    firewall { "003 allow ccs multicast via ${location} ip ${source_cidr} input":
      chain  => 'INPUT',
      proto  => all,
      source => $source_cidr,
      action => accept,
    }
    firewall { "003 allow ccs multicast via ${location} ip ${source_cidr} forward":
      chain       => 'FORWARD',
      proto       => all,
      source      => $source_cidr,
      destination => $source_cidr,
      action      => accept,
    }
    firewall { "003 allow ccs multicast via ${location} ip ${source_cidr} output":
      chain       => 'OUTPUT',
      proto       => all,
      destination => $source_cidr,
      action      => accept,
    }
  }

}

