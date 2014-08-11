#ifndef _systemd_iface_h_
#define _systemd_iface_h_

const gchar *systemd_iface =
  "<node>"
   "<interface name='org.freedesktop.systemd1.Manager'>"
    "<method name='GetUnitFileState'>"
     "<arg name='file' type='s' direction='in'/>"
     "<arg name='state' type='s' direction='out'/>"
    "</method>"
    "<method name='DisableUnitFiles'>"
     "<arg name='files' type='as' direction='in'/>"
     "<arg name='runtime' type='b' direction='in'/>"
     "<arg name='changes' type='a(sss)' direction='out'/>"
    "</method>"
    "<method name='EnableUnitFiles'>"
     "<arg name='files' type='as' direction='in'/>"
     "<arg name='runtime' type='b' direction='in'/>"
     "<arg name='force' type='b' direction='in'/>"
     "<arg name='carries_install_info' type='b' direction='out'/>"
     "<arg name='changes' type='a(sss)' direction='out'/>"
    "</method>"
    "<method name='Reload'/>"
    "<method name='StartUnit'>"
     "<arg name='name' type='s' direction='in'/>"
     "<arg name='mode' type='s' direction='in'/>"
     "<arg name='job' type='o' direction='out'/>"
    "</method>"
    "<method name='StopUnit'>"
     "<arg name='name' type='s' direction='in'/>"
     "<arg name='mode' type='s' direction='in'/>"
     "<arg name='job' type='o' direction='out'/>"
    "</method>"
    "<method name='Reload'/>"
    "<property name='Virtualization' type='s' access='read'/>"
   "</interface>"
  "</node>";

#endif
