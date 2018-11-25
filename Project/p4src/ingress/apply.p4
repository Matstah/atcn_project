// ingress apply

// DPI
bit<7> prob = 0;
inspection_probability.read(prob, 0);
bit<7> rand = 0;
//random<bit<7>>(rand,0,100);
if (rand < prob) {
    dpi();
}

// Forwarding
ip_forwarding.apply();
