/*
 * Copyright © 2013 Canonical Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the licence, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
 * USA.
 */

#include "unit.h"

G_DEFINE_TYPE (Unit, unit, G_TYPE_OBJECT)

static void
unit_init (Unit *unit)
{
}

static void
unit_class_init (UnitClass *class)
{
}

Unit *
lookup_unit (GVariant  *parameters,
             GError   **error)
{
  const gchar *unit_name;
  Unit *unit = NULL;

  g_variant_get_child (parameters, 0, "&s", &unit_name);

  if (g_str_equal (unit_name, "ntpd.service"))
    unit = ntp_unit_get ();

  if (g_str_equal (unit_name, "suspend.target"))
    unit = power_unit_new (POWER_SUSPEND);

  else if (g_str_equal (unit_name, "hibernate.target"))
    unit = power_unit_new (POWER_HIBERNATE);

  else if (g_str_equal (unit_name, "reboot.target"))
    unit = power_unit_new (POWER_REBOOT);

  else if (g_str_equal (unit_name, "shutdown.target") || g_str_equal (unit_name, "poweroff.target"))
    unit = power_unit_new (POWER_OFF);

  if (unit == NULL)
    g_set_error (error, G_DBUS_ERROR, G_DBUS_ERROR_FILE_NOT_FOUND,
                 "Unknown unit: %s", unit_name);

  return unit;
}

const gchar *
unit_get_state (Unit *unit)
{
  g_return_val_if_fail (unit != NULL, NULL);

  return UNIT_GET_CLASS (unit)->get_state (unit);
}

void
unit_start (Unit *unit)
{
  g_return_if_fail (unit != NULL);

  return UNIT_GET_CLASS (unit)->start (unit);
}

void
unit_stop (Unit *unit)
{
  g_return_if_fail (unit != NULL);

  return UNIT_GET_CLASS (unit)->stop (unit);
}
