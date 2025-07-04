# Customising

> [!NOTE]
>
> Currently theming options such as updating the CSS requires modifying the style.css file. This may be changed in the
> future to make it easier to modify.

Kanidm supports customising various aspects such as the site display name, site image, and display names and images for
each application.

## Changing the site

### Updating the display Name

By default, the display name is 'Kanidm <hostname>' which is visible when logged in. To modify the display name, run the
following

```bash
kanidm system domain set-displayname <new-display-name> -D admin
```

### Updating the site image

Similarly instead of the default Ferris the crab logo, the image on the signin page can be updated or reset with the
below commands. The image must satisfy the following conditions:

1. Maximum 1024 x 1024 pixels
2. Less than 256 KB
3. Is a supported image file type: png, jpg, gif, svg, webp

```bash
kanidm system domain set-image <file-path> [image-type] -D admin

kanidm system domain remove-image -D admin
```

## Changing a resource server

### Updating the display name

Each application can have its display name updated with the following

```bash
kanidm system oauth2 set-displayname <NAME> <displayname> -D idm_admin
```

### Updating the image

Each application can have its image updated or reset with the following commands. The image is subject to the same
restrictions as the site image above.

```bash
kanidm system oauth2 set-image <NAME> <file-path> [image-type] -D idm_admin

kanidm system oauth2 remove-image <NAME> -D idm_admin
```
