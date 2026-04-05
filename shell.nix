{ pkgs ? import <nixpkgs> {} }: pkgs.mkShell {
	nativeBuildInputs = with pkgs.buildPackages; [
		opencl-headers
		rocmPackages.clr
	];
}
