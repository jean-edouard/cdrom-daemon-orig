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

static int cdrom_vdev_of_domid(int domid)
{
  char xpath[256], **devs, *type;
  unsigned int i, count;
  int vdev = -1;

  /* Find the CDROM virtual device for the given domid */
  snprintf(xpath, sizeof(xpath), "/local/domain/0/backend/vbd/%d", domid);
  devs = xs_directory(xs_handle, XBT_NULL, xpath, &count);
  if (devs) {
    for (i = 0; i < count; ++i) {
      snprintf(xpath, sizeof(xpath), "/local/domain/0/backend/vbd/%d/%s/device-type", domid, devs[i]);
      type = xs_read(xs_handle, XBT_NULL, xpath, NULL);
      if (type != NULL && !strcmp(type, "cdrom")) {
	/* CDROM found! */
	vdev = strtol(devs[i], NULL, 10);
	break;
      }
    }
    free(devs);
  }

  return vdev;
}

static int cdrom_tap_minor_of_vdev(int domid, int vdev)
{
  char xpath[256], *tmp;
  int tap_minor = -1;

  snprintf(xpath, sizeof(xpath), "/local/domain/0/backend/vbd/%d/%d/minor", domid, vdev);
  tmp = xs_read(xs_handle, XBT_NULL, xpath, NULL);
  if (tmp != NULL)
    tap_minor = strtol(tmp, NULL, 10);

  return tap_minor;
}

static int cdrom_count_and_print(int tap_minor, int max, bool print)
{
  char **domids;
  unsigned int i, count;
  int tm, domid;
  int res = 0;

  /* Find the CDROM virtual device for the given domid */
  domids = xs_directory(xs_handle, XBT_NULL, "/local/domain/0/backend/vbd", &count);
  if (domids) {
    for (i = 0; i < count; ++i) {
      domid = strtol(domids[i], NULL, 10);
      tm = cdrom_tap_minor_of_vdev(domid, cdrom_vdev_of_domid(domid));
      if (print)
	printf("CDROM for domid %d: %d\n", domid, tm);
      if (tm == tap_minor)
	res++;
      if (res >= max)
	break;
    }
  }
  free(domids);

  return res;
}

static void cdrom_change(int domid, int vdev, char *params, char *type)
{
  char xpath[256];
  xs_transaction_t trans;

  while (1) {
    trans = xs_transaction_start(xs_handle);
    snprintf(xpath, sizeof(xpath), "/local/domain/0/backend/vbd/%d/%d/params", domid, vdev);
    xs_write(xs_handle, trans, xpath, params, 0);
    snprintf(xpath, sizeof(xpath), "/local/domain/0/backend/vbd/%d/%d/type", domid, vdev);
    xs_write(xs_handle, trans, xpath, type, 0);
    if (xs_transaction_end(xs_handle, trans, false) == false) {
      if (errno == EAGAIN)
	continue;
      break;
    }
  }
}

static bool cdrom_tap_close_and_load(int tap_minor, const char *params, bool close)
{
  tap_list_t **list, *tap = NULL;
  int count, i;

  count = tap_ctl_list(&list);
  for (i = 0; i < count; ++i) {
    if ((list[i])->minor == tap_minor) {
      tap = list[i];
      break;
    }
  }
  if (tap == NULL)
    return false;
  if (close)
    tap_ctl_close(tap->id, tap_minor, 1);
  tap_ctl_open(tap->id, tap_minor, params);
  tap_ctl_free_list(list);

  return true;
}

gboolean cdrom_daemon_change_iso(CdromDaemonObject *this,
				 const char* IN_path,
				 gint IN_domid,
				 GError** error)
{
  int tap_minor, count, vdev;
  char params[256], *new_tpath;

  /* Get the virtual cdrom vdev and tap minor for the domid */
  vdev = cdrom_vdev_of_domid(IN_domid);
  tap_minor = cdrom_tap_minor_of_vdev(IN_domid, vdev);

  /* If we don't have a virtual drive, fail. */
  if (tap_minor < 0)
    return FALSE;

  /* Eject the disk */
  cdrom_change(IN_domid, vdev, "", "");

  /* If the path is the empty string we're done. */
  if (*IN_path == '\0')
    return TRUE;

  /* See if there's more than 1 domid (us) using the tapdev */
  count = cdrom_count_and_print(tap_minor, 2, true);

  /* This should never happen */
  if (count <= 0) {
    printf("wha?!\n");
    return FALSE;
  }

  /* Insert the new iso */
  snprintf(params, sizeof(params), "aio:/dev/xen/blktap-2/tapdev%d", tap_minor);
  if (count == 1) {
    /* We're the only one to use it, we can reuse the tapdev */
    if (cdrom_tap_close_and_load(tap_minor, IN_path, true))
      cdrom_change(IN_domid, vdev, params, "phy");
  } else {
    /* We need to create a new tapdev */
    tap_ctl_create(params, &new_tpath);
    tap_minor = strtol(params + 28, NULL, 10);
    if (cdrom_tap_close_and_load(tap_minor, IN_path, false))
      cdrom_change(IN_domid, vdev, params, "phy");
  }

  return TRUE;
}
