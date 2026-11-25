"""Plain-English descriptions of model features, used to turn explanations into sentences."""
import re

NSL = {
    "duration": "how long the connection lasted (seconds)",
    "protocol_type": "network protocol (tcp, udp, icmp)",
    "service": "the service contacted (http, ftp, smtp...)",
    "flag": "how the connection ended (SF = normal, S0 = no reply, REJ = refused)",
    "src_bytes": "bytes sent by the source",
    "dst_bytes": "bytes sent back by the destination",
    "land": "source and destination are the same machine and port",
    "wrong_fragment": "number of malformed packet fragments",
    "urgent": "number of urgent packets",
    "hot": "sensitive actions seen in the session (e.g. entering system folders)",
    "num_failed_logins": "failed login attempts",
    "logged_in": "whether the login succeeded",
    "num_compromised": "signs of a compromised account",
    "root_shell": "whether an administrator (root) shell was obtained",
    "su_attempted": "attempts to switch to the administrator account",
    "num_root": "actions performed as administrator",
    "num_file_creations": "files created",
    "num_shells": "command shells opened",
    "num_access_files": "operations on access-control files",
    "num_outbound_cmds": "outbound FTP commands",
    "is_host_login": "login belongs to a host account",
    "is_guest_login": "login used a guest account",
    "count": "connections to the same host in the last 2 seconds",
    "srv_count": "connections to the same service in the last 2 seconds",
    "serror_rate": "share of recent connections to this host that failed to open (SYN errors)",
    "srv_serror_rate": "share of recent connections to this service that failed to open (SYN errors)",
    "rerror_rate": "share of recent connections to this host that were refused",
    "srv_rerror_rate": "share of recent connections to this service that were refused",
    "same_srv_rate": "share of recent connections to this host that used the same service",
    "diff_srv_rate": "share of recent connections to this host that used different services",
    "srv_diff_host_rate": "share of recent connections to this service that went to different hosts",
    "dst_host_count": "connections to this destination host (last 100 connections)",
    "dst_host_srv_count": "connections to this host and service (last 100 connections)",
    "dst_host_same_srv_rate": "share of the host's recent connections using the same service",
    "dst_host_diff_srv_rate": "share of the host's recent connections using different services",
    "dst_host_same_src_port_rate": "share of the host's recent connections from the same source port",
    "dst_host_srv_diff_host_rate": "share of the service's recent connections coming from different hosts",
    "dst_host_serror_rate": "share of the host's recent connections that failed to open",
    "dst_host_srv_serror_rate": "share of the service's recent connections that failed to open",
    "dst_host_rerror_rate": "share of the host's recent connections that were refused",
    "dst_host_srv_rerror_rate": "share of the service's recent connections that were refused",
}

CIC = {
    "destination_port": "destination port number",
    "flow_duration": "how long the flow lasted (microseconds)",
    "total_fwd_packets": "packets sent by the source",
    "total_backward_packets": "packets sent back",
    "flow_bytes_s": "bytes per second in the flow",
    "flow_packets_s": "packets per second in the flow",
    "flow_iat_mean": "average gap between packets",
    "syn_flag_count": "packets with the SYN (open) flag",
    "rst_flag_count": "packets with the RST (reset) flag",
    "fin_flag_count": "packets with the FIN (close) flag",
}


def describe(feature):
    """Plain description of a feature; falls back to a readable version of its name."""
    if feature in NSL:
        return NSL[feature]
    if feature in CIC:
        return CIC[feature]
    words = re.sub(r"_+", " ", feature)
    return (words.replace(" fwd ", " forward ").replace(" bwd ", " backward ")
            .replace(" iat ", " inter-arrival time ").replace("pkt", "packet").strip())
