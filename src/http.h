
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _VG_HTTP_H_INCLUDED_
#define _VG_HTTP_H_INCLUDED_

struct vg_ctrl;


int vg_http_listen(int port);
void vg_http_handle(struct vg_ctrl *ctrl, int fd);

#endif /* _VG_HTTP_H_INCLUDED_ */
