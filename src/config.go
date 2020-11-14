package main

import (
	"fmt"

	"github.com/traefik/paerser/flag"
)

type brconfig struct {
	Debug        bool
	NetInterface string
	Devices      map[string]bonjourDevice
}

type bonjourDevice struct {
	OriginPool  uint16   `toml:"origin_pool"`
	SharedPools []uint16 `toml:"shared_pools"`
}

func readConfig(args []string) (cfg brconfig, err error) {
	config := brconfig{}

	config.Debug = false

	if err := flag.Decode(args, &config); err != nil {
		return brconfig{}, fmt.Errorf("error reading config file, %v", err)
	}

	return config, err
}

func mapByPool(devices map[string]bonjourDevice) map[uint16]([]uint16) {
	seen := make(map[uint16]map[uint16]bool)
	poolsMap := make(map[uint16]([]uint16))
	for _, device := range devices {
		for _, pool := range device.SharedPools {
			if _, ok := seen[pool]; !ok {
				seen[pool] = make(map[uint16]bool)
			}
			if _, ok := seen[pool][device.OriginPool]; !ok {
				seen[pool][device.OriginPool] = true
				poolsMap[pool] = append(poolsMap[pool], device.OriginPool)
			}
		}
	}
	return poolsMap
}
