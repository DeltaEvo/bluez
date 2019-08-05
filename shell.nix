{ pkgs ? import <nixpkgs> {} }:

pkgs.bluez.overrideAttrs(oldAttrs: {
  nativeBuildInputs = oldAttrs.nativeBuildInputs ++
	[ pkgs.autoreconfHook ];
})
