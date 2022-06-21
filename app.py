from crypo import main, container
import sys
import crypo

if __name__ == '__main__':
    container.wire(modules=[sys.modules[__name__]], packages=[crypo])
    main()