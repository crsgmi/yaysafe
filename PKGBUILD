pkgname=yaysafe
pkgver=0.1.0
pkgrel=1
pkgdesc='Experimental security review wrapper for yay and AUR packages'
arch=('any')
url='https://github.com/crsgmi/yaysafe'
license=('MIT')
depends=('python>=3.11' 'yay' 'git')
makedepends=('python-build' 'python-installer' 'python-pytest' 'python-setuptools' 'python-wheel')
options=('!debug')
source=("git+${url}.git#tag=v${pkgver}")
b2sums=('SKIP')

build() {
  cd "$pkgname"
  python -m build --wheel --no-isolation
}

check() {
  cd "$pkgname"
  python -m pytest
}

package() {
  cd "$pkgname"
  python -m installer --destdir="$pkgdir" dist/*.whl
  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
  install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
}
