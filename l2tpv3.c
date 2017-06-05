/*
 *
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h> 
#include <sys/wait.h>

#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/l2tp.h>
#include <linux/udp.h>

#include "l2tp.h"
#include "libnetlink.h"

static struct rtnl_handle genl_rth;
static int genl_family = -1;

static int
genl_parse_getfamily(struct nlmsghdr *nlh)
{
	struct rtattr *tb[CTRL_ATTR_MAX + 1];
	struct genlmsghdr *ghdr = NLMSG_DATA(nlh);
	int len = nlh->nlmsg_len;
	struct rtattr *attrs;

	if (nlh->nlmsg_type != GENL_ID_CTRL) {
		fprintf(stderr, "Not a controller message, nlmsg_len=%d "
			"nlmsg_type=0x%x\n", nlh->nlmsg_len, nlh->nlmsg_type);
		return -1;
	}

	if (ghdr->cmd != CTRL_CMD_NEWFAMILY) {
		fprintf(stderr, "Unknown controller command %d\n", ghdr->cmd);
		return -1;
	}

	len -= NLMSG_LENGTH(GENL_HDRLEN);

	if (len < 0) {
		fprintf(stderr, "wrong controller message len %d\n", len);
		return -1;
	}

	attrs = (struct rtattr *) ((char *) ghdr + GENL_HDRLEN);
	parse_rtattr(tb, CTRL_ATTR_MAX, attrs, len);

	if (tb[CTRL_ATTR_FAMILY_ID] == NULL) {
		fprintf(stderr, "Missing family id TLV\n");
		return -1;
	}

	return rta_getattr_u16(tb[CTRL_ATTR_FAMILY_ID]);
}

static int
genl_ctrl_resolve_family(const char *family)
{
	struct {
		struct nlmsghdr n;
		struct genlmsghdr g;
		char buf[1024];
	} req;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = GENL_ID_CTRL;
	req.g.cmd = CTRL_CMD_GETFAMILY;

	addattr_l(&req.n, 1024, CTRL_ATTR_FAMILY_NAME, family, strlen(family) + 1);

	if (rtnl_talk(&genl_rth, &req.n, 0, 0, &req.n) < 0) {
		fprintf(stderr, "Error talking to the kernel\n");
		return -2;
	}

	return genl_parse_getfamily(&req.n);
}

static int
l2tpv3_get_ifname(_u32 tunnel_id, _u32 peer_tunnel_id,
	_u32 session_id, _u32 peer_session_id, char *ifname, int len)
{
	struct {
		struct nlmsghdr n;
		struct genlmsghdr g;
		char buf[128];
	} req;

	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char buf[16384];
	int status;
	int msglen = 0;
	struct nlmsghdr *h;

	struct genlmsghdr *ghdr;
	int nlmsg_len;
	struct rtattr *attrs[L2TP_ATTR_MAX + 1];

	if (!ifname) {
		l2tp_log(LOG_CRIT, "%s: !ifname\n", __FUNCTION__);
		return -1;
	}

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_type = genl_family;
	req.n.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
	req.n.nlmsg_seq = genl_rth.dump = ++genl_rth.seq;

	req.g.cmd = L2TP_CMD_SESSION_GET;
	req.g.version = L2TP_GENL_VERSION;

	addattr32(&req.n, 128, L2TP_ATTR_CONN_ID, tunnel_id);
	addattr32(&req.n, 128, L2TP_ATTR_SESSION_ID, session_id);

	if (rtnl_send(&genl_rth, &req, req.n.nlmsg_len) < 0)
		return -2;

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	status = recvmsg(genl_rth.fd, &msg, 0);
	if (status <= 0) {
		l2tp_log(LOG_CRIT, "%s: status <= 0\n", __FUNCTION__);
		return -1;
	}

	h = (struct nlmsghdr*)buf;
	msglen = status;
	while (NLMSG_OK(h, msglen)) {
		ghdr = NLMSG_DATA(h);
		nlmsg_len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*ghdr));
		if (nlmsg_len < 0)
			return -1;

		parse_rtattr(attrs, L2TP_ATTR_MAX, (void *)ghdr + GENL_HDRLEN, nlmsg_len);

		if (attrs[L2TP_ATTR_IFNAME]) {
			strncpy(ifname, rta_getattr_str(attrs[L2TP_ATTR_IFNAME]), len);
			return 0;
		}

		h = NLMSG_NEXT(h, msglen);
	}

	return -1;
}

static int
l2tpv3_run_script(struct call *c, char *updown)
{
	struct tunnel *t = c->container;
	char *script = NULL;
	char ifname[80];
	char cmd[1024];
	int len;

	if (c->lns && strlen(c->lns->script) > 0)
		script = c->lns->script;
	if (c->lac && strlen(c->lac->script) > 0)
		script = c->lac->script;

	if (!script)
		return 0;

	if (!l2tpv3_get_ifname(t->ourtid, t->tid, c->ourcid, c->cid, ifname, 80)) {
		len = snprintf(cmd, 1024, "%s %s %s", script, ifname, updown);
		if (len > 1024 - 1) {
			l2tp_log(LOG_CRIT, "%s: script path too long\n", __FUNCTION__);
			return -1;
		}
		system(cmd);
	} else {
		l2tp_log(LOG_CRIT, "%s: l2tpv3_get_ifname fail\n", __FUNCTION__);
	}

	return 0;
}

int
l2tpv3_create_tunnel(struct tunnel *t)
{
	struct {
		struct nlmsghdr n;
		struct genlmsghdr g;
		char buf[1024];
	} req;
	struct sockaddr_in local, remote;
	int flags;
	int ufd = -1;

	if (t->udp_fd > -1) {
		l2tp_log(LOG_DEBUG, "%s : exists?\n", __FUNCTION__);
		return -1;
	}

	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = t->my_addr.ipi_addr.s_addr;
	local.sin_port = htons(gconfig.port);
	if ((ufd = socket (PF_INET, SOCK_DGRAM, 0)) < 0) {
		l2tp_log(LOG_CRIT, "%s: Unable to allocate UDP socket. Terminating.\n",
			__FUNCTION__);
		return -EINVAL;
	}

	//flags = 1;
	//setsockopt(ufd, IPPROTO_UDP, UDP_ENCAP_L2TPINUDP, &flags, sizeof(flags));

	flags = 1;
	setsockopt(ufd, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags));

	if (bind(ufd, (struct sockaddr *)&local, sizeof(local))) {
		close(ufd);
		l2tp_log(LOG_CRIT, "%s: Unable to bind UDP socket: %s. Terminating.\n",
			__FUNCTION__, strerror(errno), errno);
		return -EINVAL;
	}

	memset(&remote, 0, sizeof(remote));
	remote.sin_family = AF_INET;
	remote.sin_addr.s_addr = t->peer.sin_addr.s_addr;
	remote.sin_port = t->peer.sin_port;
	flags = fcntl(ufd, F_GETFL);
	if (flags == -1 || fcntl(ufd, F_SETFL, flags | O_NONBLOCK) == -1) {
		l2tp_log(LOG_WARNING, "%s: Unable to set UDP socket nonblock.\n",
			__FUNCTION__);
		return -EINVAL;
	}

	if (connect(ufd, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
		l2tp_log(LOG_CRIT, "%s: Unable to connect UDP peer. Terminating.\n",
			__FUNCTION__);
		return -EINVAL;
	}

	t->udp_fd = ufd;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_type = genl_family;
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.g.cmd = L2TP_CMD_TUNNEL_CREATE;
	req.g.version = L2TP_GENL_VERSION;

	addattr32(&req.n, 1024, L2TP_ATTR_CONN_ID, t->ourtid);
	addattr32(&req.n, 1024, L2TP_ATTR_PEER_CONN_ID, t->tid);
	addattr8(&req.n, 1024, L2TP_ATTR_PROTO_VERSION, 3);
	addattr16(&req.n, 1024, L2TP_ATTR_ENCAP_TYPE, L2TP_ENCAPTYPE_UDP);
	addattr32(&req.n, 1024, L2TP_ATTR_FD, t->udp_fd);

	if (rtnl_talk(&genl_rth, &req.n, 0, 0, NULL) < 0) {
		l2tp_log(LOG_CRIT, "%s: rtnl_talk failed\n", __FUNCTION__);
		return -2;
	}

	return 0;
}

int
l2tpv3_create_session(struct call *c)
{
	struct {
		struct nlmsghdr n;
		struct genlmsghdr g;
		char buf[1024];
	} req;
	char *ifname = NULL;

	if (c->lac && strlen(c->lac->ifname) > 0)
		ifname = c->lac->ifname;
	if (c->lns && strlen(c->lns->ifname) > 0)
		ifname = c->lns->ifname;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_type = genl_family;
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.g.cmd = L2TP_CMD_SESSION_CREATE;
	req.g.version = L2TP_GENL_VERSION;

	addattr32(&req.n, 1024, L2TP_ATTR_CONN_ID, c->container->ourtid);
	addattr32(&req.n, 1024, L2TP_ATTR_PEER_CONN_ID, c->container->tid);
	addattr32(&req.n, 1024, L2TP_ATTR_SESSION_ID, c->ourcid);
	addattr32(&req.n, 1024, L2TP_ATTR_PEER_SESSION_ID, c->cid);
	addattr16(&req.n, 1024, L2TP_ATTR_PW_TYPE, L2TP_PWTYPE_ETH);
	addattr8(&req.n, 1024, L2TP_ATTR_L2SPEC_TYPE, L2TP_L2SPECTYPE_NONE);
	addattr8(&req.n, 1024, L2TP_ATTR_L2SPEC_LEN, 0);
	addattr16(&req.n, 1024, L2TP_ATTR_MTU, 1500);
	addattr16(&req.n, 1024, L2TP_ATTR_MRU, 1500);

	if (ifname)
		addattrstrz(&req.n, 1024, L2TP_ATTR_IFNAME, ifname);

	if (rtnl_talk(&genl_rth, &req.n, 0, 0, NULL) < 0) {
		l2tp_log(LOG_CRIT, "%s: rtnl_talk failed\n", __FUNCTION__);
		return -2;
	}

	l2tpv3_run_script(c, "up");

	return 0;
}

int
l2tpv3_delete_tunnel(struct tunnel *t)
{
	struct {
		struct nlmsghdr n;
		struct genlmsghdr g;
		char buf[1024];
	} req;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_type = genl_family;
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.g.cmd = L2TP_CMD_TUNNEL_DELETE;
	req.g.version = L2TP_GENL_VERSION;

	addattr32(&req.n, 128, L2TP_ATTR_CONN_ID, t->ourtid);

	if (rtnl_talk(&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}

int
l2tpv3_delete_session(struct call *c)
{
	struct {
		struct nlmsghdr n;
		struct genlmsghdr g;
		char buf[128];
	} req;

	l2tpv3_run_script(c, "down");

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_type = genl_family;
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.g.cmd = L2TP_CMD_SESSION_DELETE;
	req.g.version = L2TP_GENL_VERSION;

	addattr32(&req.n, 1024, L2TP_ATTR_CONN_ID, c->container->ourtid);
	addattr32(&req.n, 1024, L2TP_ATTR_SESSION_ID, c->ourcid);

	if (rtnl_talk(&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}

int
init_l2tpv3()
{
	if (genl_family < 0) {
		if (rtnl_open_byproto(&genl_rth, 0, NETLINK_GENERIC) < 0) {
			fprintf(stderr, "Cannot open generic netlink socket\n");
			return -1;
		}

		genl_family = genl_ctrl_resolve_family(L2TP_GENL_NAME);
		if (genl_family < 0)
			return -1;
	}
	return 0;
}

