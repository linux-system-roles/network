export LSR_MOLECULE_DEPS='-rmolecule_requirements.txt'

case "x${TRAVIS_PYTHON_VERSION}" in
  x3.5)
    LSR_EXTRA_PACKAGES='python3-selinux'
    ;;
  x3.6|x)
    # Set these also if we are running locally:
    export LSR_TEXTRA_DEPS='PyYAML'
    export LSR_TEXTRA_DIR='tests'
    export LSR_TEXTRA_CMD='./ensure_non_running_provider.py'
    ;;
esac
