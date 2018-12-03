// tables and actions for dpi

//
action clone_for_dpi() {
    meta.clone_id = 1;
    meta.ingress_port = standard_metadata.ingress_port;
    clone3(CloneType.I2E, 100, meta);
}

// action set_dpi_metas() {
//     bit<7> prob;
//     bit<1> debugging;
//     inspection_probability.read(prob, 0);
//     options.read(debugging, 0);
//     bit<7> rand;
//     random(rand,(bit<7>) 0, (bit<7>) 100);
//     if (rand < prob) {
//         meta.dpi_activated = 1;
//         inspected_flows.write(meta.flow_id, 1); // the flow is regesiterd for DPI
//     }
//     if (debugging > 0) {
//         meta.debugging = 1;
//     }
// }

action random_select_for_dpi() {
    bit<7> prob;
    inspection_probability.read(prob, 0);
    bit<7> rand;
    random(rand,(bit<7>) 0, (bit<7>) 100);

    bit<1> inspect_bit = 0; // because registers cannot be written conditionally
    if (rand < prob) {
        meta.flow_is_new = 1;
        inspect_bit = 1;
    }
    inspected_flows.write(meta.flow_id, inspect_bit);
}

action deselect_for_dpi() {
    inspected_flows.write(meta.flow_id, 0);
}
