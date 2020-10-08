# Generating Static Site Content

## Install Hugo

```bash
brew install hugo
```

## Install Ananke Hugo Theme

```bash
cd tests/sample_site
git clone https://github.com/budparr/gohugo-theme-ananke.git themes/ananke
```

## Generate static site content

```bash
hugo -D
```

The generated site will be in the `public` subdirectory.
