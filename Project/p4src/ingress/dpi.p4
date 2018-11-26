// tables and actions for dpi

//
action clone_for_dpi() {
    meta.ingress_port = standard_metadata.ingress_port;
    clone3(CloneType.I2E, 100, meta);
}

action set_dpi_metas() {
    bit<7> prob = 0;
    bit<7> debugging = 0;
    inspection_probability.read(prob, 0);
    inspection_probability.read(debugging, 1);
    bit<7> rand;
    random(rand,(bit<7>) 0, (bit<7>) 100);
    if (rand < prob) {
        meta.dpi_activated = 1;
    }
    if (debugging > 0) {
        meta.debugging = 1;
    }
}
