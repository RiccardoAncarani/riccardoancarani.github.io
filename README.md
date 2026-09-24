# riccardoancarani.github.io

Personal blog, built with [Hugo](https://gohugo.io/) and the
[hugo-theme-console](https://github.com/mrmierzejewski/hugo-theme-console) theme.

## Local development

```sh
hugo server
# → http://localhost:1313
```

## Structure

- `content/posts/` — blog posts (date in the filename, e.g. `2023-08-03-attacking-an-edr-part-1.md`)
- `content/about/` — about page
- `static/` — static assets (`assets/` holds per-post images, `img/` misc)
- `layouts/` — site-level overrides of the theme's layouts
- `themes/hugo-theme-console/` — the theme (git submodule)

## Deployment

Pushing to `master` triggers `.github/workflows/hugo.yaml`, which builds the
site with Hugo and deploys it to GitHub Pages (Pages source must be set to
"GitHub Actions" in the repo settings).

## Customizing

Site-level style overrides can be added in `assets/css/custom.css`
(see the theme README for available CSS variables).
