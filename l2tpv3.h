/*
 *
 */

int l2tpv3_create_tunnel(struct tunnel *t);
int l2tpv3_create_session(struct call *c);
int l2tpv3_delete_tunnel(struct tunnel *t);
int l2tpv3_delete_session(struct call *c);
int init_l2tpv3();
