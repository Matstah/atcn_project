// ingress apply

// DPI
set_dpi_metas();
if((meta.dpi_activated > 0) || (meta.debugging > 0)) { // Note: conditions can not be moved to actions
    clone_for_dpi();
}

// Forwarding
ip_forwarding.apply();
