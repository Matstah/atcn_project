// actions for dpi

// set ID for DPI and clone packet
action clone_for_dpi() {
    meta.clone_id = 1;
    meta.ingress_port = standard_metadata.ingress_port;
    clone3(CloneType.I2E, 100, meta);
}

// a new flow is selected by a user-defined probability
action random_select_for_dpi() {
    bit<7> prob;
    inspection_probability.read(prob, 0);
    bit<7> rand;
    random(rand,(bit<7>) 0, (bit<7>) 100);

    // because registers cannot be written conditionally,
    // we have to make a detour...
    bit<1> inspect_bit = 0;
    if (rand < prob) {
        meta.flow_is_new = 1;
        inspect_bit = 1;
    }
    inspected_flows.write(meta.flow_id, inspect_bit);
}

// reset bit if the flow should no longer be inspected (e.g. because of timeout)
action deselect_for_dpi() {
    inspected_flows.write(meta.flow_id, 0);
}
