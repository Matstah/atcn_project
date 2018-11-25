// tables and actions for dpi
action dpi() {
    meta.ingress_port = standard_metadata.ingress_port;
    clone3(CloneType.I2E, 100, meta);
}
