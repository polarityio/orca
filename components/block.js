polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  maxTagsToShow: 50,
  maxAssetsToShow: 50,
  showTags: false,
  showAssets: false,
  numTagsShown: 0,
  numAssetsShown: 0,

  init() {
    this.set(
      'numTagsShown',
      Math.min(this.get('maxTagsToShow'), this.get('details.data.0.tags_list.length')),
    );
    this.set(
      'numAssetsShown',
      Math.min(this.get('maxAssetsToShow'), this.get('details.data.length')),
    );

    this._super(...arguments);
  },
  actions: {
    toggleShowTags: function () {
      this.toggleProperty(`showTags`);
      this.get('block').notifyPropertyChange('data');
    },
    toggleShowAssets: function () {
      this.toggleProperty(`showAssets`);
      this.get('block').notifyPropertyChange('data');
    }
  }
});
