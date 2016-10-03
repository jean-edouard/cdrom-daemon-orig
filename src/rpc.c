/*
 * Copyright (c) 2016 Assured Information Security, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * @file   rpc.c
 * @author Jed Lejosne <lejosnej@ainfosec.com>
 * @date   03 Oct 2016
 *
 * @brief  DBus service
 *
 * Implementation of the dbus methods we expose
 */

#include "project.h"

#define SERVICE "com.citrix.xenclient.cdromdaemon"
#define SERVICE_OBJ_PATH "/"

static DBusConnection  *g_dbus_conn = NULL;
static DBusGConnection *g_glib_dbus_conn = NULL;

/**
 * @brief Initialize the DBus RPC bits
 *
 * Grab the bus, initialize the xcdbus handle and export the server.
 */
void rpc_init(void)
{
  CdromDaemonObject *server_obj = NULL;

  g_glib_dbus_conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, NULL);
  if (!g_glib_dbus_conn) {
    log(LOG_ERR, "no bus");
    exit(1);
  }
  g_dbus_conn = dbus_g_connection_get_connection(g_glib_dbus_conn);
  g_xcbus = xcdbus_init2(SERVICE, g_glib_dbus_conn);
  if (!g_xcbus) {
    log(LOG_ERR, "failed to init dbus connection / grab service name");
    exit(1);
  }
  /* export server object */
  server_obj = cdrom_daemon_export_dbus(g_glib_dbus_conn, SERVICE_OBJ_PATH);
  if (!server_obj) {
    log(LOG_ERR, "failed to export server object");
    exit(1);
  }
}

gboolean cdrom_daemon_change_iso(CdromDaemonObject *this,
				 const char* IN_path,
				 gint IN_domid,
				 GError** error)
{
  /* tap_list_t tap; */
  char xpath[256], **devs, *type;
  int domid = IN_domid;
  unsigned int count, i;
  int id = 0;
  xs_transaction_t trans;

  /* Find the CDROM virtual device for the give domid */
  snprintf(xpath, sizeof(xpath), "/local/domain/0/backend/vbd/%d", domid);
  devs = xs_directory(xs_handle, XBT_NULL, xpath, &count);
  if (devs) {
    for (i = 0; i < count; ++i) {
      snprintf(xpath, sizeof(xpath), "/local/domain/0/backend/vbd/%d/%s/device-type", domid, devs[i]);
      type = xs_read(xs_handle, XBT_NULL, xpath, NULL);
      if (type != NULL && !strcmp(type, "cdrom")) {
	/* CDROM found! */
	id = strtol(devs[i], NULL, 10);
	break;
      }
    }
    free(devs);
  }
  if (id == 0)
    return FALSE;

  /* Eject the disk */
  while (1) {
    trans = xs_transaction_start(xs_handle);
    snprintf(xpath, sizeof(xpath), "/local/domain/0/backend/vbd/%d/%d/params", domid, id);
    xs_write(xs_handle, trans, xpath, "", 0);
    snprintf(xpath, sizeof(xpath), "/local/domain/0/backend/vbd/%d/%d/type", domid, id);
    xs_write(xs_handle, trans, xpath, "", 0);
    if (xs_transaction_end(xs_handle, trans, false) == false) {
      if (errno == EAGAIN)
	continue;
      break;
    }
  }

  /* TODO: load the new iso */
  /* tap-ctl close [...] */
  /* tap-ctl open -p 2139 -m 5 -a aio:/storage/isos/xc-tools.iso */
  /* xenstore-write /local/domain/0/backend/vbd/4/5632/params "/dev/xen/blktap-2/tapdev5" ; xenstore-write local/domain/0/backend/vbd/4/5632/type "aio" */

  return TRUE;
}
