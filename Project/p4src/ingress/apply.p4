// ingress apply

// DPI
bit<7> prob = 0;
inspection_probability.read(prob, 0);
bit<7> rand;
random(rand,(bit<7>) 0, (bit<7>) 100);
if (rand < prob) {
    dpi();
}

// Forwarding
ip_forwarding.apply();
