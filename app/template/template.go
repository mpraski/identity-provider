package template

import (
	"embed"
	"io"

	"github.com/unrolled/render"
)

type (
	Renderer struct {
		render *render.Render
	}

	Params = map[string]interface{}
)

func NewRenderer(files embed.FS) *Renderer {
	return &Renderer{
		render: render.New(render.Options{
			Layout:     "layout",
			Directory:  "templates",
			FileSystem: &render.EmbedFileSystem{FS: files},
			Extensions: []string{".tmpl"},
			// Other
			RenderPartialsWithoutPrefix: true,
		}),
	}
}

func (r *Renderer) Render(w io.Writer, status int, template string, params Params) error {
	return r.render.HTML(w, status, template, params)
}
