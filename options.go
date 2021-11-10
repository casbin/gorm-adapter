package gormadapter

type adapterOptions struct {
	autoMigrate bool
}

type Option func(options *adapterOptions)

func defaultAdapterOptions() adapterOptions {
	return adapterOptions{
		autoMigrate: true,
	}
}

func WithAutoMigrate(autoMigrate bool) Option {
	return func(o *adapterOptions) {
		o.autoMigrate = autoMigrate
	}
}
